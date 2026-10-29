"""Review probes: fake APIs only; no native engine or target is launched.

Assertions confirm the observed defects, NOT product acceptance.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]

def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

w = load('review_commercial_worker', 'worker/ig5_worker.py')
w._open = True
w._resolve_ea = lambda params: 0x1000
observations = []

# 1. Repeatable comments must restore their own channel.
comments = {False: 'ordinary-old', True: 'repeatable-old'}
def set_comment(ea, text, repeatable):
    comments[repeatable] = text
    return True
modules = {name: SimpleNamespace() for name in ['ida_funcs', 'ida_name', 'ida_nalt', 'ida_typeinf']}
modules['ida_bytes'] = SimpleNamespace(get_cmt=lambda ea, rpt: comments[rpt], set_cmt=set_comment)
with patch.dict(sys.modules, modules):
    w._op_journal.clear()
    w.m_comment({'ea': '0x1000', 'text': 'repeatable-new', 'repeatable': True})
    undone = w.m_undo({})
assert undone['ok'] is True and comments[True] == 'repeatable-new'
observations.append({'id': 'R1', 'undo': undone, 'commentsAfterUndo': comments})

# 2. An explicitly supplied, mismatching expected value is ignored.
registers = {'rax': 0x11}
writes = []
def set_reg(name, value):
    registers[name] = value
    return True
dbg = SimpleNamespace(DSTATE_NOTASK=0, DSTATE_RUN=1, DSTATE_SUSP=-1,
    get_process_state=lambda: -1, get_reg_val=lambda name: registers[name], set_reg_val=set_reg)
idd = SimpleNamespace(dbg_read_memory=lambda ea, size: b'\x11' * size,
    dbg_write_memory=lambda ea, data: writes.append(data.hex()) or True)
with patch.dict(sys.modules, {'ida_dbg': dbg, 'ida_idaapi': SimpleNamespace(BADADDR=2**64-1), 'ida_idd': idd}):
    reg = w.m_dbg({'op': 'setreg', 'reg': 'rax', 'value': '0x22', 'expected': '0x99'})
    mem = w.m_dbg({'op': 'writemem', 'ea': '0x1000', 'hex': '22', 'expected': '99'})
assert reg['ok'] is True and registers['rax'] == 0x22 and mem['ok'] is True and writes == ['22']
observations.append({'id': 'R2', 'registerResult': reg, 'memoryResult': mem, 'writes': writes})

# 3. Both analysis APIs fail, but the primitive reports success.
calls = []
def broken(*args):
    calls.append(args)
    raise RuntimeError('fixture analysis unavailable')
with patch.dict(sys.modules, {'ida_auto': SimpleNamespace(auto_mark_range=broken, auto_wait=broken),
                             'ida_bytes': SimpleNamespace(), 'ida_funcs': SimpleNamespace()}):
    result = w.m_analyze({'action': 'reanalyze', 'ea': '0x1000'})
assert result['ok'] is True and len(calls) == 2
observations.append({'id': 'R3', 'failedApiCalls': len(calls), 'result': result})

# 4. entries is advertised by the public tool but is rejected here; exports
# accepts every analysis entry, including an ordinary program entrypoint.
entry = SimpleNamespace(get_entry_qty=lambda: 1, get_entry_ordinal=lambda index: 1,
    get_entry=lambda ordinal: 0x1000, get_entry_name=lambda ordinal: 'program_entry_only')
with patch.dict(sys.modules, {'ida_entry': entry, 'ida_loader': SimpleNamespace(),
                             'ida_nalt': SimpleNamespace(), 'ida_segment': SimpleNamespace()}):
    exports = w.m_listing({'kind': 'exports'})
    try:
        w.m_listing({'kind': 'entries'})
    except ValueError as exc:
        rejected = str(exc)
    else:
        raise AssertionError('entries unexpectedly supported')
assert exports['items'][0]['name'] == 'program_entry_only'
observations.append({'id': 'R4', 'exports': exports, 'entriesError': rejected})

# 5. Cleanup never confirms process exit, yet error_result claims cleanedUp.
a = load('review_x64_adapter', 'adapters/x64dbg/adapter.py')
adapter = a.Adapter.__new__(a.Adapter)
import threading
import collections
adapter.client = None
adapter.job = a.KillJob.__new__(a.KillJob)
adapter.job.handle = 1
adapter.job.kernel = SimpleNamespace(CloseHandle=lambda handle: 0)
adapter.log = None
adapter.run_id = 'fixture-run'
adapter.stop_seq = 1
adapter.mode = 'headless'
adapter.event_lock = threading.Lock()
adapter.events = collections.deque()
class SurvivingProcess:
    pid = 424242
    stdin = None
    def poll(self): return None
    def wait(self, timeout): raise subprocess.TimeoutExpired('fixture', timeout)
    def kill(self): raise OSError('fixture termination denied')
survivor = SurvivingProcess()
adapter.proc = survivor
with patch.object(a.subprocess, 'run', side_effect=OSError('fixture taskkill denied')):
    result = adapter.error_result(a.RpcError('ETIMEDOUT', 'fixture deadline'))
assert survivor.poll() is None and result['cleanedUp'] is True and adapter.proc is None
observations.append({'id': 'R5', 'result': result, 'actualExitConfirmed': False, 'processHandleRetained': adapter.proc is not None})

print(json.dumps({'nativeLaunches': 0, 'observations': observations}, ensure_ascii=False, indent=2))
