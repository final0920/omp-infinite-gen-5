"""2026-10-24 独立评审 R1-R5 的回归测试：复现脚本 docs/review/review-20261024/reproduce_python.py 的断言取反。

只使用模拟 API 与模拟进程，不启动样本、调试器或任何原生引擎。
运行：runtimes/ghidra/python/python.exe -I -B -X utf8 scripts/test_review_20261024_python.py
"""
import collections
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = load('review_fix_commercial_worker', 'worker/ig5_worker.py')
w._open = True
w._resolve_ea = lambda params: 0x1000
results = []


def check(name):
    def wrap(fn):
        try:
            fn()
            results.append({'name': name, 'ok': True})
            print('PASS', name)
        except Exception as error:  # noqa: BLE001 - report every failure, then exit non-zero
            results.append({'name': name, 'ok': False, 'error': repr(error)})
            print('FAIL', name, repr(error))
        return fn
    return wrap


# ---------------------------------------------------------------- R1
def comment_modules(comments):
    def set_comment(ea, text, repeatable):
        comments[bool(repeatable)] = text
        return True
    modules = {name: SimpleNamespace() for name in ['ida_funcs', 'ida_name', 'ida_nalt', 'ida_typeinf']}
    modules['ida_bytes'] = SimpleNamespace(get_cmt=lambda ea, rpt: comments[bool(rpt)], set_cmt=set_comment)
    return modules


@check('R1: undo of a repeatable comment restores the repeatable channel and leaves the ordinary one alone')
def _():
    comments = {False: 'ordinary-old', True: 'repeatable-old'}
    with patch.dict(sys.modules, comment_modules(comments)):
        w._op_journal.clear()
        w.m_comment({'ea': '0x1000', 'text': 'repeatable-new', 'repeatable': True})
        assert comments[True] == 'repeatable-new' and comments[False] == 'ordinary-old'
        undone = w.m_undo({})
    assert undone['ok'] is True and undone['repeatable'] is True and undone['restored'] is True, undone
    assert comments == {False: 'ordinary-old', True: 'repeatable-old'}, comments


@check('R1: ordinary comments still undo, and a legacy journal entry without the channel field is treated as ordinary')
def _():
    comments = {False: 'ordinary-old', True: 'repeatable-old'}
    with patch.dict(sys.modules, comment_modules(comments)):
        w._op_journal.clear()
        w.m_comment({'ea': '0x1000', 'text': 'ordinary-new'})
        assert w.m_undo({})['ok'] is True and comments[False] == 'ordinary-old'
        comments[False] = 'changed'
        w._op_journal.append({'kind': 'comment', 'ea': 0x1000, 'old': 'legacy-old'})
        assert w.m_undo({})['ok'] is True and comments[False] == 'legacy-old' and comments[True] == 'repeatable-old'


# ---------------------------------------------------------------- R2
def debugger_fixture(initial_reg=0x11):
    registers, writes = {'rax': initial_reg}, []

    def set_reg(name, value):
        registers[name] = value
        return True
    dbg = SimpleNamespace(DSTATE_NOTASK=0, DSTATE_RUN=1, DSTATE_SUSP=-1, get_process_state=lambda: -1,
                          get_reg_val=lambda name: registers[name], set_reg_val=set_reg)
    memory = {'bytes': b'\x11'}

    def write_memory(ea, data):
        writes.append(data.hex())
        memory['bytes'] = bytes(data)
        return True
    idd = SimpleNamespace(dbg_read_memory=lambda ea, size: (memory['bytes'] * size)[:size], dbg_write_memory=write_memory)
    modules = {'ida_dbg': dbg, 'ida_idaapi': SimpleNamespace(BADADDR=2**64 - 1), 'ida_idd': idd}
    return registers, writes, memory, modules


@check('R2: setreg with a mismatching expected value writes nothing')
def _():
    registers, writes, memory, modules = debugger_fixture()
    with patch.dict(sys.modules, modules):
        result = w.m_dbg({'op': 'setreg', 'reg': 'rax', 'value': '0x22', 'expected': '0x99'})
    assert result['ok'] is False and result['written'] is False and registers['rax'] == 0x11, result
    assert result['expected'] == '0x99' and result['actual'] == '0x11'


@check('R2: setreg with a matching expected value (or none) still writes and verifies the result')
def _():
    registers, writes, memory, modules = debugger_fixture()
    with patch.dict(sys.modules, modules):
        assert w.m_dbg({'op': 'setreg', 'reg': 'rax', 'value': '0x22', 'expected': '0x11'})['ok'] is True
        assert registers['rax'] == 0x22
        assert w.m_dbg({'op': 'setreg', 'reg': 'rax', 'value': '0x33'})['ok'] is True
    assert registers['rax'] == 0x33


@check('R2: writemem with a mismatching, wrong-length or unreadable expected value writes nothing')
def _():
    registers, writes, memory, modules = debugger_fixture()
    with patch.dict(sys.modules, modules):
        mismatch = w.m_dbg({'op': 'writemem', 'ea': '0x1000', 'hex': '22', 'expected': '99'})
        assert mismatch['ok'] is False and mismatch['written'] == 0 and mismatch['actual'] == '11' and writes == [], mismatch
        try:
            w.m_dbg({'op': 'writemem', 'ea': '0x1000', 'hex': '2222', 'expected': '99'})
        except ValueError:
            pass
        else:
            raise AssertionError('a length mismatch between expected and data must be rejected')
        modules['ida_idd'].dbg_read_memory = lambda ea, size: None
        unreadable = w.m_dbg({'op': 'writemem', 'ea': '0x1000', 'hex': '22', 'expected': '11'})
        assert unreadable['ok'] is False and unreadable['written'] == 0 and writes == [], unreadable


@check('R2: writemem with a matching expected value writes')
def _():
    registers, writes, memory, modules = debugger_fixture()
    with patch.dict(sys.modules, modules):
        result = w.m_dbg({'op': 'writemem', 'ea': '0x1000', 'hex': '22', 'expected': '11'})
    assert result['ok'] is True and writes == ['22'], result


# ---------------------------------------------------------------- R3
@check('R3: reanalyze / mark_code report failure when the analysis APIs fail')
def _():
    calls = []

    def broken(*args):
        calls.append(args)
        raise RuntimeError('fixture analysis unavailable')
    with patch.dict(sys.modules, {'ida_auto': SimpleNamespace(auto_mark_range=broken, auto_wait=broken),
                                  'ida_bytes': SimpleNamespace(), 'ida_funcs': SimpleNamespace()}):
        for action in ('reanalyze', 'mark_code'):
            result = w.m_analyze({'action': action, 'ea': '0x1000'})
            assert result['ok'] is False and result['partial'] is False, result
            assert 'auto_mark_range' in result['error'] and 'auto_wait' in result['error']
    assert len(calls) == 4


@check('R3: one failing step is reported as partial, a cancelled wait is a failure, and success stays success')
def _():
    def broken(*args):
        raise RuntimeError('mark failed')
    with patch.dict(sys.modules, {'ida_auto': SimpleNamespace(auto_mark_range=broken, auto_wait=lambda: True),
                                  'ida_bytes': SimpleNamespace(), 'ida_funcs': SimpleNamespace()}):
        partial = w.m_analyze({'action': 'reanalyze', 'ea': '0x1000'})
    assert partial['ok'] is False and partial['partial'] is True, partial
    with patch.dict(sys.modules, {'ida_auto': SimpleNamespace(auto_mark_range=lambda *a: None, auto_wait=lambda: False),
                                  'ida_bytes': SimpleNamespace(), 'ida_funcs': SimpleNamespace()}):
        cancelled = w.m_analyze({'action': 'reanalyze', 'ea': '0x1000'})
    assert cancelled['ok'] is False and 'cancelled' in cancelled['error'], cancelled
    with patch.dict(sys.modules, {'ida_auto': SimpleNamespace(auto_mark_range=lambda *a: None, auto_wait=lambda: True),
                                  'ida_bytes': SimpleNamespace(), 'ida_funcs': SimpleNamespace()}):
        assert w.m_analyze({'action': 'reanalyze', 'ea': '0x1000'})['ok'] is True


# ---------------------------------------------------------------- R4
def listing_modules(extra=None):
    entry = SimpleNamespace(get_entry_qty=lambda: 1, get_entry_ordinal=lambda index: 1,
                            get_entry=lambda ordinal: 0x1000, get_entry_name=lambda ordinal: 'program_entry_only')
    modules = {'ida_entry': entry, 'ida_loader': SimpleNamespace(), 'ida_nalt': SimpleNamespace(get_imagebase=lambda: 0x140000000),
               'ida_segment': SimpleNamespace(), 'ida_bytes': SimpleNamespace(get_bytes=lambda ea, size: None)}
    modules.update(extra or {})
    return modules


@check('R4: entries lists analysis entry points and says they are not exports')
def _():
    with patch.dict(sys.modules, listing_modules()):
        entries = w.m_listing({'kind': 'entries'})
    assert entries['items'][0]['name'] == 'program_entry_only'
    assert entries['semantics'] == 'analysis-entrypoints-not-export-table', entries


@check('R4: exports never fall back to analysis entry points; without an export directory the result is partial/unsupported')
def _():
    with patch.dict(sys.modules, listing_modules()):
        exports = w.m_listing({'kind': 'exports'})
    assert exports['items'] == [] and exports['partial'] is True and exports['unsupported'] is True, exports
    assert 'program_entry_only' not in json.dumps(exports) and exports['source'] == 'pe-export-directory'


@check('R4: exports come from the PE export directory reader when it is available')
def _():
    fake = SimpleNamespace(pe_exports=lambda read, base: {'rows': [{'name': 'RealExport', 'ordinal': 1}], 'partial': False})
    with patch.dict(sys.modules, listing_modules({'pe_exports': fake})):
        exports = w.m_listing({'kind': 'exports'})
    assert [row['name'] for row in exports['items']] == ['RealExport'] and exports['total'] == 1, exports
    assert exports['source'] == 'pe-export-directory' and 'program_entry_only' not in json.dumps(exports)


# ---------------------------------------------------------------- R5
a = load('review_fix_x64_adapter', 'adapters/x64dbg/adapter.py')


def make_adapter(proc, close_result):
    adapter = a.Adapter.__new__(a.Adapter)
    adapter.client = None
    adapter.job = a.KillJob.__new__(a.KillJob)
    adapter.job.handle = 1
    adapter.job.kernel = SimpleNamespace(CloseHandle=lambda handle: close_result)
    adapter.log = None
    adapter.run_id = 'fixture-run'
    adapter.stop_seq = 1
    adapter.mode = 'headless'
    adapter.event_lock = threading.Lock()
    adapter.events = collections.deque()
    adapter.proc = proc
    return adapter


class SurvivingProcess:
    pid = 424242
    stdin = None

    def poll(self):
        return None

    def wait(self, timeout):
        raise subprocess.TimeoutExpired('fixture', timeout)

    def kill(self):
        raise OSError('fixture termination denied')


class ExitedProcess:
    pid = 424243
    stdin = None

    def poll(self):
        return 0

    def wait(self, timeout):
        return 0


@check('R5: an unconfirmed cleanup does not claim cleanedUp and keeps the process and job references')
def _():
    survivor = SurvivingProcess()
    adapter = make_adapter(survivor, 0)
    with patch.object(a.subprocess, 'run', side_effect=OSError('fixture taskkill denied')):
        result = adapter.error_result(a.RpcError('ETIMEDOUT', 'fixture deadline'))
    assert result['cleanedUp'] is False and result['cleanupConfirmed'] is False, result
    assert result['state'] == 'cleanup-unconfirmed' and result['debuggerPid'] == 424242, result
    assert adapter.proc is survivor and adapter.job is not None and adapter.job.handle == 1, 'evidence must be retained for a retry'


@check('R5: a failed job close is not confirmed even if the process already exited, and can be retried')
def _():
    adapter = make_adapter(ExitedProcess(), 0)
    assert adapter.cleanup() is False and adapter.job is not None
    adapter.job.kernel = SimpleNamespace(CloseHandle=lambda handle: 1)
    assert adapter.cleanup() is True and adapter.job is None and adapter.proc is None


@check('R5: a confirmed cleanup still reports cleanedUp with the no-task state')
def _():
    adapter = make_adapter(ExitedProcess(), 1)
    result = adapter.error_result(a.RpcError('ETIMEDOUT', 'fixture deadline'))
    assert result['cleanedUp'] is True and result['cleanupConfirmed'] is True and result['state'] == 'no-task', result
    assert adapter.proc is None and adapter.job is None


@check('R5: close refuses to report success without confirmation, and no second debugger starts over an unconfirmed one')
def _():
    survivor = SurvivingProcess()
    adapter = make_adapter(survivor, 0)
    adapter.target = {'bits': 64}
    adapter.deadline = None
    adapter.cancel = threading.Event()
    adapter.timeout_seconds = lambda params: 5
    with patch.object(a.subprocess, 'run', side_effect=OSError('fixture taskkill denied')):
        try:
            adapter.dispatch('close', {})
        except a.RpcError as error:
            assert error.code == 'ECLEANUP' and error.detail['cleanedUp'] is False, error.detail
            assert adapter.target == {'bits': 64}, 'the target registration must be kept when close is not confirmed'
        else:
            raise AssertionError('close must not report success while the debugger process is not confirmed exited')
    assert adapter.proc is survivor
    try:
        adapter.launch()
    except a.RpcError as error:
        assert error.code == 'ESTATE' and error.detail['cleanedUp'] is False, error.detail
    else:
        raise AssertionError('launch must refuse while the previous debugger process is not confirmed exited')


failed = [row for row in results if not row['ok']]
print(json.dumps({'ok': not failed, 'passed': len(results) - len(failed), 'failed': len(failed), 'nativeLaunches': 0}, ensure_ascii=False))
sys.exit(1 if failed else 0)
