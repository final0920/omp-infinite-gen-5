"""Transport/state regressions with a fake debugger; never launches a target."""
import importlib.util
import io
from pathlib import Path
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "adapters/x64dbg/adapter.py"
spec = importlib.util.spec_from_file_location("ig5_x64dbg_adapter", SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class FakeClient:
    def __init__(self, adapter):
        self.adapter = adapter
        self.debugging, self.running = True, False
        self.regs = {"rip": 0x140001000, "rax": 1, "eflags": 0x202}
        self.memory = bytearray(b"\x01\x02\x03\x04")
        self.writes = []
        self.commands = []
        self.command_result, self.step_events, self.exit_on_command = True, True, False

    def is_debugging(self): return self.debugging
    def is_running(self): return self.running
    def eval_sync(self, value):
        return (0x140000000 if value == "mod.main()" else 0x4000 if value.startswith("mod.size(")
                else self.regs.get("rip", self.regs.get("eip")) if value == "cip" else self.regs[value]), True
    def get_regs(self): return SimpleNamespace(context=SimpleNamespace(model_dump=lambda: self.regs.copy()))
    def read_memory(self, ea, size): return bytes(self.memory[:size])
    def write_memory(self, ea, data): self.writes.append((ea, data)); self.memory[:len(data)] = data; return True
    def set_reg(self, name, value): self.writes.append((name, value)); self.regs[name] = value; return True
    def set_breakpoint(self, ea): self.writes.append(("bpt", ea)); return True
    def clear_breakpoint(self, ea): self.writes.append(("unbpt", ea)); return True
    def cmd_sync(self, command):
        self.commands.append(command)
        if self.exit_on_command:
            self.debugging = False
            self.adapter.record_event(SimpleNamespace(event_type="EVENT_EXIT_PROCESS", event_data={"dwExitCode": 1}))
        elif self.step_events:
            self.regs["rip"] += 1
            for typ in ("EVENT_PAUSE_DEBUG", "EVENT_STEPPED"):
                self.adapter.record_event(SimpleNamespace(event_type=typ, event_data={}))
        return self.command_result


class AdapterTests(unittest.TestCase):
    def test_explicit_exception_handling_is_bound_to_current_native_pause(self):
        class Native(FakeClient, mod.NativeClient):
            def close(self): pass
        self.client = self.adapter.client = Native(self.adapter)
        self.adapter.native_run_epoch = 1
        self.adapter.state = lambda: {'state': 'suspended', 'stopSeq': self.adapter.stop_seq, 'runId': 'test-run', 'tid': 9, 'nativeRunEpoch': 1}
        self.adapter.context = self.adapter.state
        self.adapter.wait_state = lambda *args: {'ok': True, 'state': 'suspended'}
        self.adapter.mode = 'headless'
        pipe = io.BytesIO()
        self.adapter.proc = SimpleNamespace(stdin=pipe, pid=123, poll=lambda: 0)
        self.adapter.job = SimpleNamespace(handle=1, close=lambda: None)
        self.adapter.check = lambda: None
        with self.assertRaisesRegex(mod.RpcError, 'observed exception pause'):
            self.dbg('cont', exception_disposition='handled')
        self.assertEqual(self.client.commands, [])
        self.adapter.record_event(SimpleNamespace(event_type='EVENT_EXCEPTION',
            event_data={'ExceptionCode': 0x80000003, 'ExceptionAddress': 0x140001002, 'dwFirstChance': True},
            native_stop_seq=1, native_run_epoch=1))
        result = self.dbg('cont', exception_disposition='handled')
        self.assertEqual(pipe.getvalue(), b'serun\n')
        self.assertEqual(self.client.commands, [])
        self.assertEqual(result['continuedException']['code'], '0x80000003')
        self.assertEqual(result['continuedException']['stopSeq'], 1)
        self.assertEqual(result['exceptionDisposition'], 'handled')
        # A newer stop cannot consume the previous exception; neither can an
        # exception from a stale run epoch that happens to share its stop number.
        self.adapter.stop_seq = 3
        with self.assertRaisesRegex(mod.RpcError, 'observed exception pause'):
            self.dbg('cont', exception_disposition='handled')
        self.adapter.record_event(SimpleNamespace(event_type='EVENT_EXCEPTION', event_data={}, native_stop_seq=3, native_run_epoch=2))
        with self.assertRaisesRegex(mod.RpcError, 'observed exception pause'):
            self.dbg('cont', exception_disposition='handled')
        self.assertEqual(pipe.getvalue(), b'serun\n')
        self.assertEqual(self.client.commands, [])

    def test_debug_environment_parameters_refuse_before_side_effects(self):
        for op, params in [('regs', {'anti_debug_profile': 'scyllahide-thread-context'}),
            ('start', {'anti_debug_profile': 'arbitrary'}), ('step', {'exception_disposition': 'handled'}),
            ('cont', {'exception_disposition': 'serun;arbitrary'}), ('start', {'anti_debug_profile': 'scyllahide-thread-context'})]:
            with self.assertRaises(mod.RpcError): self.dbg(op, **params)
        self.adapter.mode = 'headless'; self.adapter.config['bridge'] = 'ig5-native'
        with patch.object(mod, 'inspect_pe', return_value={'bits': 32}):
            with self.assertRaisesRegex(mod.RpcError, 'override must be x64'):
                self.dbg('start', anti_debug_profile='scyllahide-thread-context', path='OWN-32-bit.exe')
        self.assertEqual(self.client.commands, [])

    def test_continuation_wait_does_not_raise_other_operation_budgets(self):
        self.assertEqual(mod.Adapter.timeout_seconds({'op': 'cont', 'timeout': 120}), 120)
        self.assertEqual(mod.Adapter.timeout_seconds({'op': 'cont', 'timeout': 121}), 120)
        for operation in ('trace', 'step', 'start', 'regs'):
            self.assertEqual(mod.Adapter.timeout_seconds({'op': operation, 'timeout': 120}), 60)
        with self.assertRaisesRegex(ValueError, 'finite'): mod.Adapter.timeout_seconds({'op': 'cont', 'timeout': float('inf')})

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ig5-x64dbg-fake-")
        self.adapter = mod.Adapter(Path(self.temp.name) / "runtime.json")
        self.adapter.target = {"path": "fake.exe", "bits": 64, "databaseBase": "0x140000000", "entryRVA": "0x1000"}
        self.adapter.run_id = "test-run"
        self.client = self.adapter.client = FakeClient(self.adapter)

    def tearDown(self):
        self.adapter.cleanup()
        self.temp.cleanup()

    def dbg(self, op, **params): return self.adapter.dispatch("dbg", {"op": op, **params})

    def test_open_registers_without_execution(self):
        self.adapter.client = None
        p = Path(self.temp.name) / "空白.exe"
        data = bytearray(0x200); data[:2] = b"MZ"; struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"; struct.pack_into("<H", data, 0x84, 0x8664)
        struct.pack_into("<H", data, 0x98, 0x20b); struct.pack_into("<I", data, 0xa8, 0x1000); struct.pack_into("<Q", data, 0xb0, 0x140000000)
        p.write_bytes(data)
        opened = self.adapter.dispatch("open", {"path": str(p)})
        self.assertFalse(opened["targetExecuted"]); self.assertIsNone(self.adapter.proc)
        self.assertEqual(opened["target"]["bits"], 64)
        data[0x98:0x9a] = b"\x0b\x01"; p.write_bytes(data)
        with self.assertRaises(mod.RpcError) as error: self.adapter.dispatch("open", {"path": str(p)})
        self.assertEqual(error.exception.code, "EINVAL")

    def test_integer_rejects_lossy_and_boolean(self):
        for value in (True, 1.2, None, [], "1.2"):
            with self.assertRaises((ValueError, TypeError)): mod.integer(value)
        self.assertEqual(mod.integer("0x123"), 0x123)

    def test_native_thread_stack_and_hardware_contract(self):
        class FakeNative(FakeClient, mod.NativeClient):
            def close(self): pass
            def drain(self): pass
            def request(self, method, **params):
                if method != 'state': raise AssertionError('Unexpected native snapshot method')
                return {'debugging': self.debugging, 'running': self.running, 'pid': 7, 'tid': 9}
            def module_info(self, ea): return {"found": True, "base": "0x140000000", "size": 0x4000, "name": "fake.exe", "path": "fake.exe"}
            def get_threads(self): return {"threads": [{"threadId": 9, "current": True}], "total": 1, "truncated": False}
            def get_callstack(self): return {"frames": [{"index": 0, "from": "0x140001000"}], "threadId": 9, "heuristic": True}
            def set_breakpoint(self, ea, kind, access, size):
                self.writes.append((ea, kind, access, size)); return {"ok": True, "exists": True, "slot": 2, "size": size}
            def clear_breakpoint(self, ea, kind, access, size): return {"ok": True, "exists": False}
        self.client = self.adapter.client = FakeNative(self.adapter)
        self.assertTrue(self.dbg("threads")["native"])
        self.assertTrue(self.dbg("callstack")["heuristic"])
        result = self.dbg("bpt", rva="0x1000", kind="hardware", access="write", size=4)
        self.assertEqual(result["breakpoint"]["slot"], 2)
        self.assertEqual(self.client.writes, [(0x140001000, "hardware", "write", 4)])
        self.assertTrue(self.dbg("unbpt", rva="0x1000", kind="hardware")["ok"])
        self.client.running = True
        for op in ("threads", "callstack"):
            with self.assertRaises(mod.RpcError) as error: self.dbg(op)
            self.assertEqual(error.exception.code, "ESTATE")

    def test_native_idle_running_hint_never_implies_an_active_debuggee(self):
        class IdleNative(FakeClient, mod.NativeClient):
            def drain(self): pass
            def close(self): pass
            def request(self, method, **params):
                self.asserted_method = method
                return {'debugging': False, 'running': True, 'pid': 0, 'tid': 0}
        self.adapter.client = IdleNative(self.adapter)
        self.assertEqual(self.adapter.state()['state'], 'no-task')
        self.assertEqual(self.adapter.client.asserted_method, 'state')

    def test_hardware_rejects_before_native_side_effect(self):
        for params in ({"kind": "hardware", "access": "execute", "size": 4},
                       {"kind": "hardware", "access": "write", "size": 2, "rva": "0x1001"},
                       {"kind": "hardware", "access": "write;quit"},
                       {"kind": "software", "access": "write"}, {"kind": "other"}):
            with self.assertRaises(mod.RpcError) as error: self.dbg("bpt", **{"rva": "0x1000", **params})
            self.assertEqual(error.exception.code, "EINVAL")
        self.adapter.target["bits"] = 32
        with self.assertRaises(mod.RpcError): self.dbg("bpt", ea="0x401000", kind="hardware", access="write", size=8)
        self.assertEqual(self.client.writes, [])

    def test_native_only_features_do_not_guess_legacy_transport(self):
        for op, params in (("threads", {}), ("callstack", {}), ("bpt", {"kind": "hardware", "rva": "0x1000"})):
            with self.assertRaises(mod.RpcError) as error: self.dbg(op, **params)
            self.assertEqual(error.exception.code, "ENOTSUPPORTED")
        self.assertEqual(self.client.writes, [])

    def test_expected_memory_rejects_without_write(self):
        result = self.dbg("writemem", ea="0x140001000", hex="ffff", expected="0000")
        self.assertFalse(result["ok"]); self.assertEqual(self.client.writes, [])
        self.assertTrue(self.dbg("writemem", ea="0x140001000", hex="ffff", expected="0102")["ok"])
        self.assertEqual(self.client.memory[:2], b"\xff\xff")

    def test_register_width_and_expected(self):
        self.assertFalse(self.dbg("setreg", reg="rax", value="0x9", expected="0x2")["ok"])
        self.assertEqual(self.client.writes, [])
        self.assertTrue(self.dbg("setreg", reg="rax", value="0x9", expected="0x1")["ok"])
        for reg, value in (("rip", -1), ("rax", 1 << 64), ("eflags", 1 << 32), ("foo", 1)):
            with self.assertRaises(mod.RpcError) as error: self.dbg("setreg", reg=reg, value=value)
            self.assertEqual(error.exception.code, "EINVAL")

    def test_32bit_address_and_register_contract(self):
        self.adapter.target["bits"] = 32
        self.client.regs = {"eip": 0x401000, "eax": 0, "eflags": 0x202}
        with self.assertRaises(mod.RpcError): self.dbg("readmem", ea="0x100000000", size=1)
        with self.assertRaises(mod.RpcError): self.dbg("setreg", reg="rax", value=1)
        result = self.dbg("regs"); self.assertEqual(result["bits"], 32); self.assertIn("eip", result["regs"])

    def test_no_stale_pause_success(self):
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_PAUSE_DEBUG", event_data={}))
        self.client.step_events = False
        with self.assertRaises(mod.RpcError) as error: self.dbg("step", timeout=0.1)
        self.assertEqual(error.exception.code, "ETIMEDOUT"); self.assertTrue(error.exception.detail["cleanedUp"])
        self.assertEqual(error.exception.detail["state"], "no-task"); self.assertIsNone(error.exception.detail["pid"])
        self.assertIsNone(self.adapter.client)

    def test_fresh_step_and_run_context(self):
        result = self.dbg("step")
        self.assertTrue(result["ok"]); self.assertEqual(result["eventName"], "step")
        self.assertEqual(result["stopSeq"], 1); self.assertEqual(result["context"]["runId"], "test-run")
        self.assertEqual(result["context"]["RVA"], "0x1001")

    def test_exit_is_not_step_success(self):
        self.client.exit_on_command = True
        result = self.dbg("step")
        self.assertFalse(result["ok"]); self.assertEqual(result["state"], "no-task")
        self.assertEqual(result["eventName"], "process-exited")

    def test_read_bounds_and_running_guard(self):
        for size in (0, 4097):
            with self.assertRaises(mod.RpcError): self.dbg("readmem", ea=1, size=size)
        self.client.running = True
        with self.assertRaises(mod.RpcError) as error: self.dbg("regs")
        self.assertEqual(error.exception.code, "ESTATE"); self.assertEqual(self.client.writes, [])

    def test_cancellation_cleans_transport(self):
        self.client.step_events = False
        timer = threading.Timer(0.03, self.adapter.cancel.set); timer.start()
        try:
            with self.assertRaises(mod.RpcError) as error: self.dbg("step", timeout=2)
            self.assertEqual(error.exception.code, "ECANCELLED"); self.assertTrue(error.exception.detail["cleanedUp"])
        finally: timer.join()

    def test_events_are_bounded_and_exceptions_are_structured(self):
        for _ in range(300): self.adapter.record_event(SimpleNamespace(event_type="EVENT_RESUME_DEBUG", event_data={}))
        self.assertEqual(len(self.adapter.events), 256)
        self.assertTrue(self.dbg("event", after=0)["truncated"])
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_EXCEPTION", event_data={"ExceptionCode": 0xc0000005, "ExceptionAddress": 0, "ExceptionInformation": [8, 0]}))
        data = self.adapter.events[-1]["data"]
        self.assertEqual(data["ExceptionCode"], "0xc0000005"); self.assertEqual(data["ExceptionInformation"], ["0x8", "0x0"])

    def test_native_command_surface_is_typed(self):
        client = object.__new__(mod.NativeClient)
        requests = []
        client.request = lambda method, **params: requests.append((method, params)) or True
        for cmd in ('run; quit', 'init "anything.exe"', 'ticnd 0, 1; quit', 'unknown'):
            with self.assertRaises(ValueError): client.cmd_sync(cmd)
        client.cmd_sync("ticnd cip==0x1000, 0x5")
        self.assertEqual(requests, [("trace", {"count": 5, "until": "0x1000"})])

    def test_runtime_database_and_rva_address_conversion(self):
        original = self.client.eval_sync
        self.client.eval_sync = lambda expr: (0x150000000, True) if expr == "mod.main()" else original(expr)
        self.assertEqual(self.adapter.address({"rva": "0x1000"}), 0x150001000)
        self.assertEqual(self.adapter.address({"ea": "0x140001000", "addressSpace": "database"}), 0x150001000)
        self.assertEqual(self.adapter.address({"ea": "0x1000", "addressSpace": "rva"}), 0x150001000)
        self.assertEqual(self.adapter.address({"ea": "0x150001000"}), 0x150001000)

    def test_invalid_timeouts_remain_protocol_errors(self):
        for value in ("invalid", float("nan"), float("inf"), None):
            with self.assertRaises(mod.RpcError) as error: self.dbg("state", timeout=value)
            self.assertEqual(error.exception.code, "EINVAL")
        self.assertIs(self.adapter.client, self.client)

    def test_rva_rejects_negative_and_full_span_outside_module(self):
        for rva, size in (("-0x1", 1), ("0x4000", 1), ("0x3fff", 2)):
            with self.assertRaises(mod.RpcError) as error: self.dbg("readmem", rva=rva, size=size)
            self.assertEqual(error.exception.code, "EINVAL")
        with self.assertRaises(mod.RpcError): self.dbg("writemem", rva="0x3fff", hex="abcd")
        with self.assertRaises(ValueError): self.adapter.address({"ea": "0xffffffffffffffff"}, 2)
        self.assertEqual(self.adapter.address({"rva": "0x3fff"}, 1), 0x140003fff)
        self.assertEqual(self.client.writes, [])

    def test_context_resolves_current_module_and_keeps_main_identity(self):
        self.client.regs["rip"] = 0x7ff00123
        self.client.module_info = lambda ea: {"found": True, "base": "0x7ff00000", "size": 0x2000, "name": "ntdll.dll", "path": "C:/Windows/ntdll.dll"}
        context = self.adapter.context()
        self.assertEqual(context["module"], "ntdll.dll"); self.assertEqual(context["RVA"], "0x123")
        self.assertEqual(context["moduleBase"], "0x7ff00000"); self.assertEqual(context["mainModuleBase"], "0x140000000")
        self.client.module_info = lambda ea: {"found": False}
        context = self.adapter.context()
        self.assertIsNone(context["module"]); self.assertIsNone(context["moduleBase"]); self.assertNotIn("RVA", context)

    def test_directed_cancel_never_cancels_wrong_request(self):
        request = {"id": 11, "method": "dbg", "params": {"op": "cont"}}
        self.assertTrue(self.adapter.claim_request(request))
        self.assertFalse(self.adapter.cancel_request({"requestId": 12})["cancelRequested"])
        self.assertFalse(self.adapter.cancel.is_set())
        self.assertTrue(self.adapter.cancel_request({"requestId": 11})["cancelRequested"])
        self.assertTrue(self.adapter.cancel.is_set())
        self.adapter.finish_request(11)

    def test_queued_cancel_is_skipped_and_does_not_touch_active_request(self):
        self.adapter.claim_request({"id": 11})
        queued = {"id": 22, "method": "dbg", "params": {"op": "setreg", "reg": "rax", "value": 3}}
        self.adapter.enqueue(queued)
        self.assertTrue(self.adapter.cancel_request({"requestId": 22})["queued"])
        self.assertFalse(self.adapter.claim_request(self.adapter.requests.get_nowait()))
        self.assertFalse(self.adapter.cancel.is_set()); self.assertEqual(self.client.writes, [])
        self.adapter.finish_request(11)

    def test_full_regular_queue_does_not_block_control_or_cancel(self):
        self.adapter.claim_request({"id": "active"})
        for i in range(32): self.adapter.enqueue({"id": i, "method": "doctor", "params": {}})
        with self.assertRaises(mod.RpcError) as error: self.adapter.enqueue({"id": 100, "method": "doctor", "params": {}})
        self.assertEqual(error.exception.code, "EQUEUE")
        self.adapter.enqueue({"id": "pause", "method": "dbg", "params": {"op": "suspend"}})
        self.assertEqual(self.adapter.controls.qsize(), 1)
        self.assertTrue(self.adapter.cancel_request({"requestId": "active"})["cancelRequested"])

    def test_high_priority_suspend_preserves_transport_and_one_stop_epoch(self):
        responses = []; self.adapter.respond = responses.append
        self.client.running = True
        def command(cmd):
            self.client.commands.append(cmd); self.client.running = False
            self.adapter.record_event(SimpleNamespace(event_type="EVENT_PAUSE_DEBUG", event_data={}))
            return True
        self.client.cmd_sync = command
        self.adapter.enqueue({"id": 20, "method": "dbg", "params": {"op": "suspend"}})
        self.adapter.deadline = time.monotonic() + 1
        result = self.adapter.wait_state(0)
        self.assertTrue(result["ok"]); self.assertEqual(result["interruptedBy"], "suspend")
        self.assertEqual(result["stopSeq"], 1); self.assertEqual(responses[0]["result"]["stopSeq"], 1)
        self.assertIs(self.adapter.client, self.client)

    def test_stop_does_not_overtake_an_unstarted_launch(self):
        start = {"id": 10, "method": "dbg", "params": {"op": "start"}}
        stop = {"id": 11, "method": "dbg", "params": {"op": "stop"}}
        self.adapter.enqueue(start); self.adapter.enqueue(stop)
        self.assertEqual(self.adapter.next_request()["id"], 10)
        # A cached control stays available to the active start's wait loop.
        self.assertEqual(self.adapter.control_head["id"], 11)
        self.assertEqual(self.adapter.next_request()["id"], 11)

    def gap_client(self, running=False):
        """Real NativeClient drain/state implementation over a stub pipe RPC."""
        class GapNative(FakeClient, mod.NativeClient):
            is_debugging = mod.NativeClient.is_debugging
            is_running = mod.NativeClient.is_running
            def __init__(self, adapter):
                super().__init__(adapter)
                self.running, self.event_sequence = running, 0
                self.native_seq, self.native_stop, self.native_epoch = 900, 9, 1
                self.first = True
                self.listeners = {typ: [adapter.record_event] for typ in ("EVENT_BREAKPOINT", "EVENT_PAUSE_DEBUG")}
            def close(self): pass
            def module_info(self, ea):
                return {"found": True, "base": "0x140000000", "size": 0x4000,
                        "name": "fake.exe", "path": "fake.exe"}
            def request(self, method, **params):
                if method == "events":
                    if self.first:
                        self.first = False
                        return {"eventSeq": 900, "firstAvailableSeq": 645, "truncated": True,
                                "dropped": {"from": 1, "to": 644, "count": 644},
                                "events": [{"seq": 900, "type": "EVENT_BREAKPOINT", "stopSeq": 9,
                                            "data": {"addr": "0x140001000"}}]}
                    return {"eventSeq": self.native_seq, "truncated": False, "events": []}
                if method == "state":
                    return {"debugging": self.debugging, "running": self.running, "pid": 81, "tid": 82,
                            "nativeRunEpoch": self.native_epoch, "stopSeq": self.native_stop, "eventSeq": self.native_seq}
                raise AssertionError(method)
            def cmd_sync(self, command):
                self.commands.append(command)
                if command == "pause":
                    self.running = False
                    self.native_stop += 1
                    self.native_seq += 1
                return True
        self.client = self.adapter.client = GapNative(self.adapter)
        return self.client

    def test_native_first_read_history_loss_is_explicit_and_nonfatal(self):
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_EXCEPTION", event_data={"ExceptionCode": 1}))
        native = self.gap_client()
        result = self.dbg("event")
        self.assertFalse(result["ok"])
        self.assertEqual(result["historyGap"]["dropped"], {"from": 1, "to": 644, "count": 644})
        self.assertEqual(result["stopSeq"], 9)
        self.assertTrue(result["cacheInvalidated"])
        self.assertIs(self.adapter.client, native)
        self.assertNotIn("EVENT_EXCEPTION", [e["type"] for e in self.adapter.events])

    def test_native_gap_resynchronizes_and_safely_pauses_without_claiming_hit(self):
        native = self.gap_client(running=True)
        self.adapter.deadline = time.monotonic() + 5
        result = self.adapter.wait_state(0)
        self.assertFalse(result["ok"])
        self.assertEqual(result["eventName"], "history-gap")
        self.assertIsNone(result["event"])
        self.assertEqual(result["state"], "suspended")
        self.assertEqual(result["stopSeq"], 10)
        self.assertEqual(result["runId"], "test-run")
        self.assertTrue(result["pauseAttempted"])
        self.assertTrue(result["resynced"])
        self.assertFalse(result["cleanedUp"])
        self.assertFalse(result["recoveryRequired"])
        self.assertIsNone(result["context"]["exception"])
        self.assertEqual(native.commands, ["pause"])
        self.assertIs(self.adapter.client, native)

    def test_gap_blocks_writes_until_explicit_authoritative_state_refresh(self):
        native = self.gap_client()
        result = self.dbg("setreg", reg="rax", value=2)
        self.assertFalse(result["ok"])
        self.assertEqual(result["eventName"], "history-gap")
        self.assertEqual(native.writes, [])
        refreshed = self.dbg("state")
        self.assertTrue(refreshed["ok"])
        self.assertTrue(refreshed["cacheInvalidated"])
        self.assertEqual(refreshed["stopSeq"], 9)
        self.assertFalse(self.adapter.pending_history_gap)
        self.assertTrue(self.dbg("setreg", reg="rax", value=2)["ok"])
        self.assertEqual(native.writes, [("rax", 2)])

    def test_gap_on_read_only_state_does_not_pause_a_running_target(self):
        native = self.gap_client(running=True)
        refreshed = self.dbg("state")
        self.assertEqual(refreshed["state"], "running")
        self.assertTrue(refreshed["cacheInvalidated"])
        self.assertEqual(native.commands, [])
        self.assertIs(self.adapter.client, native)

    def test_unexpected_native_run_epoch_invalidates_previous_run(self):
        self.adapter.native_run_epoch = 4
        self.adapter.sync_native_state({"nativeRunEpoch": 5, "stopSeq": 2, "eventSeq": 77,
                                        "debugging": True, "pid": 80, "tid": 81})
        self.assertNotEqual(self.adapter.run_id, "test-run")
        self.assertEqual(self.adapter.stop_seq, 2)
        self.assertTrue(self.adapter.pending_history_gap)
        self.assertEqual(self.adapter.history_gap["reason"], "native-run-changed")

    def test_true_native_pipe_failure_still_cleans_up(self):
        native = self.gap_client()
        native.request = lambda *a, **kw: (_ for _ in ()).throw(mod.RpcError("ETRANSPORT", "disconnected"))
        with self.assertRaises(mod.RpcError) as error:
            self.dbg("state")
        self.assertEqual(error.exception.code, "ETRANSPORT")
        self.assertTrue(error.exception.detail["cleanedUp"])
        self.assertIsNone(self.adapter.client)

    def test_gap_recovery_pause_rejection_preserves_target_and_reports_uncertainty(self):
        native = self.gap_client(running=True)
        native.cmd_sync = lambda command: False
        self.adapter.deadline = time.monotonic() + 5
        result = self.adapter.wait_state(0)
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "running")
        self.assertTrue(result["recoveryRequired"])
        self.assertFalse(result["resynced"])
        self.assertFalse(result["cleanedUp"])
        self.assertIsNone(result["event"])
        self.assertNotIn("runtimeVA", result["context"])
        self.assertIs(self.adapter.client, native)

    def test_priority_result_does_not_reclassify_retained_hit_after_gap(self):
        native = self.gap_client()
        state = self.adapter.state()
        result = self.adapter.wait_result(0, "suspended", state, {})
        self.assertFalse(result["ok"])
        self.assertEqual(result["eventName"], "history-gap")
        self.assertIsNone(result["event"])
        self.assertIs(self.adapter.client, native)

    def test_cleanup_resets_native_event_cursor_for_a_new_debugger_process(self):
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_PAUSE_DEBUG", event_data={},
                                                  native_seq=400, native_stop_seq=100))
        self.adapter.cleanup()
        self.assertEqual(self.adapter.event_seq, 0)
        self.assertEqual(list(self.adapter.events), [])
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_PAUSE_DEBUG", event_data={},
                                                  native_seq=2, native_stop_seq=1))
        self.assertEqual(self.adapter.event_list(0)[0]["seq"], 2)

    def test_approved_asynchronous_start_does_not_look_like_an_external_run_change(self):
        self.adapter.native_run_epoch = 0
        self.adapter.expected_native_run_epoch = 1
        for epoch, active in ((0, False), (0, False), (1, True)):
            self.adapter.sync_native_state({"nativeRunEpoch": epoch, "stopSeq": 1 if active else 0,
                                            "eventSeq": 3 if active else 0, "debugging": active, "pid": 80, "tid": 81})
        self.assertEqual(self.adapter.run_id, "test-run")
        self.assertFalse(self.adapter.pending_history_gap)
        self.assertIsNone(self.adapter.expected_native_run_epoch)
        self.adapter.sync_native_state({"nativeRunEpoch": 2, "stopSeq": 0, "eventSeq": 4,
                                        "debugging": True, "pid": 90, "tid": 91})
        self.assertNotEqual(self.adapter.run_id, "test-run")
        self.assertTrue(self.adapter.pending_history_gap)

    def test_priority_stop_waits_for_an_already_accepted_native_start(self):
        self.adapter.expected_native_run_epoch = 1
        original_state = self.adapter.state
        polls = []
        def state():
            polls.append(1)
            if len(polls) == 1:
                return {"state": "no-task", "stateCode": -1}
            self.adapter.expected_native_run_epoch = None
            return original_state()
        self.adapter.state = state
        self.client.exit_on_command = True
        result = self.dbg("stop")
        self.assertTrue(result["ok"])
        self.assertEqual(result["state"], "no-task")
        self.assertEqual(self.client.commands, ["stop"])
        self.assertGreaterEqual(len(polls), 2)

    def test_stop_classification_ignores_events_from_an_older_native_run(self):
        self.adapter.native_run_epoch = 2
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_EXCEPTION", event_data={"ExceptionCode": 1},
                                                  native_seq=12, native_stop_seq=1, native_run_epoch=1))
        self.adapter.record_event(SimpleNamespace(event_type="EVENT_STEPPED", event_data={},
                                                  native_seq=13, native_stop_seq=1, native_run_epoch=2))
        result = self.adapter.wait_result(0, "suspended", {"state": "suspended"}, {})
        self.assertTrue(result["ok"])
        self.assertEqual(result["eventName"], "step")
        self.assertNotIn("exception", result["context"])

    def test_recording_fast_wait_requires_pause_then_step_in_same_epoch(self):
        class RecordingNative(FakeClient, mod.NativeClient):
            def close(self): pass
            def drain(self): pass
            def request(self, method, **params):
                return {'debugging': True, 'running': False, 'pid': 7, 'tid': 9}
        self.adapter.client = RecordingNative(self.adapter)
        original = self.adapter.state
        polls = []
        def state():
            polls.append(1)
            typ = 'EVENT_PAUSE_DEBUG' if len(polls) == 1 else 'EVENT_STEPPED'
            self.adapter.record_event(SimpleNamespace(event_type=typ, event_data={}))
            return original()
        self.adapter.state = state
        result = self.adapter.wait_state(0, recording=True)
        self.assertEqual(result['eventName'], 'step')
        self.assertGreaterEqual(len(polls), 2)
        self.assertEqual(result['stopSeq'], 1)

    def test_recording_fast_wait_refuses_pause_without_step(self):
        class RecordingNative(FakeClient, mod.NativeClient):
            def close(self): pass
            def drain(self): pass
            def request(self, method, **params):
                return {'debugging': True, 'running': False, 'pid': 7, 'tid': 9}
        self.adapter.client = RecordingNative(self.adapter)
        self.adapter.record_event(SimpleNamespace(event_type='EVENT_PAUSE_DEBUG', event_data={}))
        self.adapter.deadline = time.monotonic() + 0.02
        with self.assertRaises(mod.RpcError) as error: self.adapter.wait_state(0, recording=True)
        self.assertEqual(error.exception.code, 'ETIMEDOUT')

    def test_native_resume_callback_after_completed_step_is_not_a_new_run(self):
        class RecordingNative(FakeClient, mod.NativeClient):
            def close(self): pass
            def drain(self): pass
            def request(self, method, **params): return {'debugging': True, 'running': False, 'pid': 7, 'tid': 9}
        self.adapter.client = RecordingNative(self.adapter)
        for typ in ['EVENT_PAUSE_DEBUG', 'EVENT_STEPPED', 'EVENT_RESUME_DEBUG']:
            self.adapter.record_event(SimpleNamespace(event_type=typ, event_data={}))
        result = self.adapter.wait_state(0, recording=True, recording_start_stop=0)
        self.assertTrue(result['ok']); self.assertEqual(result['eventName'], 'step')
        self.assertTrue(result['lateResumeObserved']); self.assertEqual(result['stopSeq'], 1)

    def test_recording_soft_event_deadline_keeps_state_and_never_claims_step(self):
        result = self.adapter.wait_state(0, recording=True, recording_deadline=time.monotonic() - 1)
        self.assertFalse(result['ok']); self.assertFalse(result['stepConfirmed'])
        self.assertTrue(result['recordingWaitExpired']); self.assertIs(self.adapter.client, self.client)


if __name__ == "__main__": unittest.main(verbosity=2)
