"""Data-only recorder fixtures: real decoder, mocked native steps, no PE execution."""
from pathlib import Path
import json
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'adapters/x64dbg'))
sys.path.insert(0, str(ROOT / 'worker'))
import trace_recorder
from store_observations import capture_store_event, reserve_store_event, encode

class Adapter:
    def __init__(self, missing=False):
        self.target = {'bits': 64}
        self.info = dict(state='suspended', runId='1'*32, pid=101, tid=7, stopSeq=1, mainModuleBase='0x1000', mainModuleSize=4096)
        self.regs = {name: 0 for name in trace_recorder.GPRS}
        self.regs.update(rip=0x1000, rsp=0x8000, rax=0x1122334455667788, eflags=0x202)
        self.memory = bytes.fromhex('0807060504030201')
        self.steps, self.event_seq, self.missing = 0, 0, missing
    def check(self): pass
    def context(self): return dict(self.info)
    def state(self): return dict(self.info)
    def call(self, method, *args):
        if method == 'get_threads': return {'threads': [{'threadId': 7, 'teb': '0x7000'}]}
        if method == 'get_regs': return SimpleNamespace(context=SimpleNamespace(model_dump=lambda: dict(self.regs)))
        if method == 'read_memory':
            address, width = args
            if 0x1000 <= address < 0x1010:
                code = bytes.fromhex('48890424c3') + b'\x90'*11
                return code[address-0x1000:address-0x1000+width]
            if address == 0x8000 and width == 8:
                if self.missing and self.steps: raise ValueError('Fixture post-store unavailable')
                return self.memory
            raise ValueError('Unknown fixture address')
        if method == 'cmd_sync':
            assert args == ('sti',)
            if self.steps == 0:
                self.memory = self.regs['rax'].to_bytes(8, 'little'); self.regs['rip'] = 0x1004
            else:
                self.regs['rip'] = int.from_bytes(self.memory, 'little'); self.regs['rsp'] += 8
            self.steps += 1; self.event_seq += 1; self.info['stopSeq'] += 1
            return True
        raise AssertionError(method)
    def wait_state(self, *args, **kwargs): return {'ok': True, 'eventName': 'step', **self.context()}

class StoreObservationTests(unittest.TestCase):
    def test_real_decoder_with_mocked_steps_records_store_bytes_and_ret_read(self):
        adapter = Adapter(); result = trace_recorder.record(adapter, {'count': 8, 'record_events': True})
        events = json.loads(result['storeEventData'])
        self.assertEqual(adapter.steps, 2)
        self.assertEqual(result['traceSummary']['stopReason'], 'returned')
        self.assertEqual(events['traceSha256'], result['traceSummary']['sha256'])
        self.assertEqual(len(events['events']), 2)
        first, last = events['events']
        self.assertEqual(first['stores'], [{'address': '0x8000', 'bytes': 8, 'beforeHex': '0807060504030201',
            'afterHex': '8877665544332211', 'changed': True, 'status': 'observed'}])
        self.assertEqual(last['stores'], [])
        self.assertTrue(first['pauseIdentityMatched'] and first['completeDecodedStoreSet'])
        self.assertFalse(first['actualWriteCausalityProved'] or events['cpuWriteFootprintProved'])
        self.assertLessEqual(len(result['traceData']) + len(result['storeEventData']), 1024*1024)
    def test_legacy_recording_has_no_sidecar_or_post_store_followup(self):
        result = trace_recorder.record(Adapter(), {'count': 8})
        self.assertNotIn('storeEventData', result)
        self.assertEqual(result['traceSummary']['instructionCount'], 2)
    def test_unavailable_followup_retains_confirmed_native_prefix_and_unknown_bytes(self):
        adapter = Adapter(missing=True); result = trace_recorder.record(adapter, {'count': 8, 'record_events': True})
        event = json.loads(result['storeEventData'])['events'][0]
        self.assertEqual(adapter.steps, 1)
        self.assertEqual(result['traceSummary']['stopReason'], 'store-followup-unavailable')
        self.assertTrue(result['traceSummary']['finalSnapshotCurrent'])
        self.assertFalse(event['completeDecodedStoreSet'])
        self.assertIsNone(event['stores'][0]['afterHex']); self.assertIsNone(event['stores'][0]['changed'])
    def test_changed_pause_invalidates_all_followup_bytes(self):
        adapter = Adapter(); before = adapter.context(); after = {**before, 'stopSeq': 2}
        adapter.info['stopSeq'] = 3
        event = capture_store_event(adapter, before, before, after, 0x1000, [(0x8000, 8, adapter.memory)], 0, time.monotonic()+5)
        self.assertFalse(event['pauseIdentityMatched']); self.assertFalse(event['completeDecodedStoreSet'])
        self.assertEqual(event['stores'][0]['status'], 'pause-changed'); self.assertIsNone(event['stores'][0]['afterHex'])
    def test_deadline_does_not_read_or_execute_anything(self):
        adapter = Adapter(); state = adapter.context()
        with patch.object(adapter, 'call', side_effect=AssertionError('Unexpected read')):
            event = capture_store_event(adapter, state, state, state, 0x1000, [(0x8000, 8, adapter.memory)], 0, time.monotonic()-1)
        self.assertEqual(event['stores'][0]['status'], 'deadline'); self.assertEqual(adapter.steps, 0)
    def test_cancellation_is_not_converted_into_an_unavailable_read(self):
        adapter = Adapter(); state = adapter.context()
        error = RuntimeError('cancel'); error.code = 'ECANCELLED'
        with patch.object(adapter, 'call', side_effect=error), self.assertRaisesRegex(RuntimeError, 'cancel'):
            capture_store_event(adapter, state, state, state, 0x1000, [(0x8000, 8, adapter.memory)], 0, time.monotonic()+5)
    def test_pre_step_reservation_covers_worst_case_and_rejects_bounds(self):
        adapter = Adapter(); state = adapter.context(); stores = [(0x8000, 8, adapter.memory)] * 32
        event = capture_store_event(adapter, state, state, state, 0x1000, stores, 511, time.monotonic()+5)
        self.assertLessEqual(len(encode(event)), reserve_store_event(stores))
        for stores in [[(0x8000, 8, b'\0'*8)]*33, [(0x8000, 257, b'\0'*257)], [(True, 1, b'\0')], [(2**64-1, 2, b'\0\0')]]:
            with self.assertRaises(ValueError): reserve_store_event(stores)
    def test_recording_rejects_bad_feature_type_before_any_step(self):
        adapter = Adapter()
        with self.assertRaisesRegex(ValueError, 'boolean'): trace_recorder.record(adapter, {'record_events': 1})
        self.assertEqual(adapter.steps, 0)

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--emit-fixtures':
        rows = [{'name': name, 'recordEvents': enabled, 'result': trace_recorder.record(Adapter(missing=missing), {'count': 8, 'record_events': enabled})}
                for name, enabled, missing in [('legacy', False, False), ('stores', True, False), ('unavailable', True, True)]]
        with Path(sys.argv[2]).open('x', encoding='utf-8') as output:
            json.dump({'nativeTargetExecuted': False, 'nativeStepsMocked': True, 'cases': rows}, output)
        print(json.dumps({'passed': True, 'fixtures': 3, 'nativeTargetExecuted': False, 'nativeStepsMocked': True}))
    else:
        unittest.main(verbosity=2)
