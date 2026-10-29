"""Offline API-trace tests: PE import parsing, taxonomy aggregation, and bounded orchestration.

No debugger is launched and no target executes. The runtime test is separate.
Run with the bundled Python: `runtimes\\ghidra\\python\\python.exe -I -B -X utf8 scripts\\test_api_trace.py`.
"""
import importlib.util
import json
import struct
import sys
import tempfile
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters" / "x64dbg"
WORKER = ROOT / "worker"
for path in (str(ADAPTER), str(WORKER)):
    if path not in sys.path:
        sys.path.insert(0, path)

import pe_imports
import api_trace
import api_trace_summary


def build_pe(bits=64, import_rva=0x2000, import_size=60, name_nul=True):
    """Small deterministic PE with two DLLs, three names and one ordinal."""
    width = 8 if bits == 64 else 4
    optional_size = 0xF0 if bits == 64 else 0xE0
    data = bytearray(0x3400)
    def u16(offset, value): struct.pack_into("<H", data, offset, value)
    def u32(offset, value): struct.pack_into("<I", data, offset, value)
    def u64(offset, value): struct.pack_into("<Q", data, offset, value)
    def text(offset, value): data[offset:offset + len(value)] = value
    text(0, b"MZ"); u32(0x3C, 0x80); text(0x80, b"PE\0\0")
    coff, optional = 0x84, 0x98
    u16(coff, 0x8664 if bits == 64 else 0x14C); u16(coff + 2, 3); u16(coff + 16, optional_size)
    u16(coff + 18, 0x22 if bits == 64 else 0x102)
    u16(optional, 0x20B if bits == 64 else 0x10B)
    data[optional + 2] = 14
    u32(optional + 4, 0x200); u32(optional + 16, 0x1000); u32(optional + 20, 0x2000)
    if bits == 64:
        u64(optional + 24, 0x140000000); u32(optional + 32, 0x1000); u32(optional + 36, 0x200)
        u32(optional + 56, 0x4000); u32(optional + 60, 0x200); u16(optional + 68, 3)
        u64(optional + 72, 0x100000); u64(optional + 80, 0x1000)
        u64(optional + 88, 0x100000); u64(optional + 96, 0x1000)
        u32(optional + 108, 16); directory = optional + 112
    else:
        u32(optional + 28, 0x400000); u32(optional + 32, 0x1000); u32(optional + 36, 0x200)
        u32(optional + 56, 0x4000); u32(optional + 60, 0x200); u16(optional + 68, 3)
        u32(optional + 72, 0x100000); u32(optional + 76, 0x1000)
        u32(optional + 80, 0x100000); u32(optional + 84, 0x1000)
        u32(optional + 92, 16); directory = optional + 96
    u32(directory + 8, import_rva); u32(directory + 12, import_size)
    # Raw pointers mirror RVAs here so the fixture's tables can be written at one offset.
    sections = [(b".text", 0x1000, 0x200, 0x1000, 0x60000020),
                (b".rdata", 0x2000, 0x400, 0x2000, 0x40000040),
                (b".data", 0x3000, 0x400, 0x3000, 0xC0000040)]
    table = optional + optional_size
    for index, (name, va, size, raw, flags) in enumerate(sections):
        row = table + index * 40
        text(row, name); u32(row + 8, size); u32(row + 12, va); u32(row + 16, size)
        u32(row + 20, raw); u32(row + 36, flags)
    # Import descriptors.
    for index, (original, name_rva, first) in enumerate(((0x2040, 0x2080, 0x3000), (0x2060, 0x2090, 0x3020))):
        row = 0x2000 + index * 20
        u32(row, original); u32(row + 12, name_rva); u32(row + 16, first)
    text(0x2080, b"KERNEL32.dll\0"); text(0x2090, b"USER32.dll\0")
    def thunk(offset, value):
        if bits == 64: u64(offset, value)
        else: u32(offset, value)
    ordinal = (1 << (bits - 1)) | 5
    for index, value in enumerate((0x20A0, 0x20C0, ordinal)):
        thunk(0x2040 + index * width, value); thunk(0x3000 + index * width, value)
    thunk(0x2060, 0x20E0); thunk(0x3020, 0x20E0)
    for offset, name in ((0x20A0, b"IsDebuggerPresent"), (0x20C0, b"GetTickCount64"), (0x20E0, b"Sleep")):
        u16(offset, 0); text(offset + 2, name + b"\0")
    if not name_nul:
        data[0x20A2:0x20A2 + 513] = b"A" * 513
    return bytes(data)


def write(tmp, data):
    path = Path(tmp) / "fixture.exe"
    path.write_bytes(data)
    return path


class ImportTests(unittest.TestCase):
    def test_pe64_imports_keep_names_ordinals_and_iat_rvas(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = pe_imports.parse_imports(write(tmp, build_pe(64)))
        self.assertEqual(plan["schema"], "ig5.pe-imports.v1")
        self.assertEqual(plan["bits"], 64)
        self.assertEqual(plan["imageBase"], 0x140000000)
        self.assertEqual(plan["modules"], ["KERNEL32.dll", "USER32.dll"])
        self.assertEqual([row["name"] for row in plan["imports"]],
                         ["IsDebuggerPresent", "GetTickCount64", "#5", "Sleep"])
        self.assertEqual([row["iatRva"] for row in plan["imports"]], [0x3000, 0x3008, 0x3010, 0x3020])
        self.assertTrue(plan["imports"][2]["byOrdinal"])
        self.assertEqual(plan["imports"][2]["ordinal"], 5)
        self.assertFalse(plan["truncated"])
        self.assertEqual(plan["delayImportDirectoryRva"], 0)

    def test_pe32_imports_use_four_byte_thunks_and_ordinal_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = pe_imports.parse_imports(write(tmp, build_pe(32)))
        self.assertEqual(plan["bits"], 32)
        self.assertEqual([row["name"] for row in plan["imports"]],
                         ["IsDebuggerPresent", "GetTickCount64", "#5", "Sleep"])
        self.assertEqual([row["iatRva"] for row in plan["imports"]], [0x3000, 0x3004, 0x3008, 0x3020])

    def test_non_pe_and_out_of_bounds_headers_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.exe"
            path.write_bytes(b"ELF" + b"\0" * 100)
            with self.assertRaisesRegex(pe_imports.ImportParseError, "missing MZ"):
                pe_imports.parse_imports(path)
            bad = bytearray(build_pe(64)); struct.pack_into("<I", bad, 0x3C, 0x7FFFFFFF)
            path.write_bytes(bad)
            with self.assertRaisesRegex(pe_imports.ImportParseError, "header offset"):
                pe_imports.parse_imports(path)

    def test_import_rva_into_unbacked_section_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = bytearray(build_pe(64))
            # .rdata raw pointer beyond EOF while the RVA remains in-range.
            struct.pack_into("<I", bad, 0x188 + 40 + 20, 0x7FFFFFF0)
            with self.assertRaisesRegex(pe_imports.ImportParseError, "outside the file|unbacked"):
                pe_imports.parse_imports(write(tmp, bytes(bad)))

    def test_unterminated_import_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(pe_imports.ImportParseError, "not NUL terminated"):
                pe_imports.parse_imports(write(tmp, build_pe(64, name_nul=False)))

    def test_no_import_directory_is_an_explicit_empty_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = pe_imports.parse_imports(write(tmp, build_pe(64, import_rva=0, import_size=0)))
        self.assertEqual(plan["imports"], [])
        self.assertEqual(plan["warnings"], [])


class SummaryTests(unittest.TestCase):
    def rows(self, *items):
        return [{"index": index, "api": name, "threadId": thread} for index, (name, thread) in enumerate(items, 1)]

    def test_categories_and_uncategorized_names(self):
        summary = api_trace_summary.summarize(self.rows(
            ("OpenProcess", 1), ("ReadProcessMemory", 1), ("WriteFile", 1), ("Sleep", 1), ("ZwOpenProcess", 2)))
        self.assertEqual(summary["schema"], "ig5.apiTraceBehavior.v1")
        process = [row for row in summary["categories"] if row["category"] == "process-access"]
        file_io = [row for row in summary["categories"] if row["category"] == "file-io"]
        self.assertEqual(sum(row["calls"] for row in process), 3)
        self.assertEqual(sum(row["distinctApis"] for row in process), 3)
        self.assertEqual(sum(row["calls"] for row in file_io), 1)
        self.assertTrue(all(row["weak"] for row in file_io))
        self.assertTrue(all(not row["weak"] for row in process))
        self.assertEqual(summary["uncategorizedApis"], ["Sleep"])
        self.assertEqual(summary["callCount"], 5)

    def test_chain_is_thread_scoped(self):
        together = api_trace_summary.summarize(self.rows(("OpenProcess", 1), ("ReadProcessMemory", 1)))
        self.assertIn("foreign-process-memory-read", [row["id"] for row in together["chains"]])
        split = api_trace_summary.summarize(self.rows(("OpenProcess", 1), ("ReadProcessMemory", 2)))
        self.assertNotIn("foreign-process-memory-read", [row["id"] for row in split["chains"]])

    def test_distinct_rule_and_missing_thread_do_not_form_a_chain(self):
        summary = api_trace_summary.summarize([
            {"index": 1, "api": "IsDebuggerPresent", "threadId": 7},
            {"index": 2, "api": "CheckRemoteDebuggerPresent", "threadId": 7},
            {"index": 3, "api": "OpenProcess", "threadId": None},
            {"index": 4, "api": "ReadProcessMemory", "threadId": None},
        ])
        self.assertIn("multiple-debugger-checks", [row["id"] for row in summary["chains"]])
        self.assertNotIn("foreign-process-memory-read", [row["id"] for row in summary["chains"]])
        self.assertEqual(summary["chains"][0]["threadId"], 7)

    def test_call_list_size_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "at most 4096"):
            api_trace_summary.summarize([{"index": 1, "api": "Sleep", "threadId": 1}] * 4097)


class FakeClient:
    pass


class FakeAdapter:
    def __init__(self, path, bits, base, memory, hits, rsp=0x700000, thread=0x1234, clear_ok=True,
                 state_raises=None):
        self.target = {"path": str(path), "bits": bits}
        self.client = FakeClient()
        self.base, self.bits, self.hits = base, bits, list(hits)
        # Expand sparse ranges to bytes so range reads (stack arguments) work too.
        self.memory = {}
        for ea, data in memory.items():
            for index, byte in enumerate(data):
                self.memory[ea + index] = byte
        self.rsp, self.thread, self.clear_ok = rsp, thread, clear_ok
        self.state_raises = list(state_raises or [])
        self.event_seq, self.deadline = 0, None
        self.run_id, self.stop_seq, self.state_value = "run-api", 5, "suspended"
        self.set_rows, self.clear_rows = [], []
        self.regs = {}
        self.the_thread = thread

    def require_pause(self):
        if self.state_value != "suspended":
            raise ValueError("operation requires a suspended process")

    def check(self):
        pass

    def context(self):
        return {"state": self.state_value, "runId": self.run_id, "stopSeq": self.stop_seq,
                "pid": 0x444, "tid": self.the_thread, "mainModuleBase": hex(self.base),
                "mainModuleSize": 0x4000}

    def state(self):
        if self.state_raises:
            error = self.state_raises.pop(0)
            if error is not None:
                raise error
        return {"state": self.state_value, "runId": self.run_id, "stopSeq": self.stop_seq,
                "pid": 0x444 if self.state_value != "no-task" else None,
                "tid": self.the_thread if self.state_value != "no-task" else None}

    def call(self, name, *args):
        if name == "read_memory":
            ea, size = args
            if all(ea + index in self.memory for index in range(size)):
                return bytes(self.memory[ea + index] for index in range(size))
            return b""
        if name == "set_breakpoint":
            self.set_rows.append(args[0]); return {"ok": True, "exists": True}
        if name == "clear_breakpoint":
            self.clear_rows.append(args[0]); return {"ok": self.clear_ok, "exists": False}
        if name == "get_regs":
            return types.SimpleNamespace(context=types.SimpleNamespace(model_dump=lambda: dict(self.regs)))
        if name == "get_threads":
            return {"threads": [{"threadId": self.the_thread, "current": True}]}
        if name == "module_info":
            raise AttributeError("module_info is not part of the fake adapter")
        if name == "cmd_sync":
            return args[0] == "run"
        raise AssertionError("unexpected fake call: " + name)

    def wait_state(self, mark):
        if not self.hits:
            self.state_value = "no-task"
            return {"ok": True, "state": "no-task", "stopSeq": self.stop_seq, "event": None}
        kind, address, regs = self.hits.pop(0)
        self.regs = dict(regs)
        self.stop_seq += 1
        if kind == "exception":
            return {"ok": True, "state": "suspended", "stopSeq": self.stop_seq,
                    "event": {"eventName": "exception", "data": {"ExceptionCode": "0xc0000005"}}}
        return {"ok": True, "state": "suspended", "stopSeq": self.stop_seq,
                "event": {"eventName": "breakpoint", "data": {"addr": hex(address), "hitCount": 1}}}


def x64_memory(base, pointers, rsp=0x700000, return_address=None):
    # IAT slots in the fixture are 0x3000, 0x3008, 0x3010 (KERNEL32) and 0x3020 (USER32).
    slots = (0x3000, 0x3008, 0x3010, 0x3020)
    memory = {base + slot: value.to_bytes(8, "little") for slot, value in zip(slots, pointers)}
    memory[rsp] = (return_address if return_address is not None else base + 0x1100).to_bytes(8, "little")
    return memory


def x64_regs(address, rsp=0x700000):
    return {"rip": address, "rsp": rsp, "rcx": 0x11, "rdx": 0x22, "r8": 0x33, "r9": 0x44}


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = 0x140000000
        self.path = write(self.tmp.name, build_pe(64))
        self.addresses = [0x7FF800001000, 0x7FF800002000, 0x7FF800003000, 0x7FF800004000]

    def adapter(self, hits, pointers=None, **kwargs):
        return FakeAdapter(self.path, 64, self.base, x64_memory(self.base, pointers or self.addresses), hits, **kwargs)

    def test_requested_apis_record_arguments_and_clear_breakpoints(self):
        adapter = self.adapter([("breakpoint", self.addresses[0], x64_regs(self.addresses[0])),
                                ("breakpoint", self.addresses[3], x64_regs(self.addresses[3]))])
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent", "Sleep"], "max_api_calls": 2})
        self.assertTrue(result["ok"])
        self.assertEqual(result["schema"], "ig5.apiTrace.v1")
        self.assertEqual(result["evidenceLevel"], "E1")
        self.assertEqual(result["coverage"]["stopReason"], "call-budget")
        self.assertTrue(result["coverage"]["callsTruncated"])
        self.assertEqual([row["api"] for row in result["calls"]], ["IsDebuggerPresent", "Sleep"])
        self.assertEqual(result["calls"][0]["arguments"]["values"][0], {"name": "rcx", "value": "0x11"})
        self.assertEqual(result["calls"][0]["threadId"], 0x1234)
        self.assertEqual(result["calls"][0]["callerRva"], "0x1100")
        self.assertEqual(adapter.set_rows, self.addresses[:1] + self.addresses[3:])
        self.assertEqual(sorted(adapter.clear_rows), sorted(adapter.set_rows))
        self.assertTrue(result["coverage"]["breakpointCleanup"]["cleared"])
        self.assertEqual(result["coverage"]["continuations"], 2)
        self.assertTrue(result["nativeTargetExecuted"])

    def test_process_exit_ends_the_trace_without_cleanup_claim(self):
        adapter = self.adapter([("breakpoint", self.addresses[0], x64_regs(self.addresses[0]))])
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent"], "max_api_calls": 8})
        self.assertEqual(result["coverage"]["stopReason"], "process-exited")
        self.assertEqual(len(result["calls"]), 1)
        self.assertFalse(result["coverage"]["breakpointCleanup"]["attempted"])
        self.assertEqual(result["coverage"]["breakpointCleanup"]["reason"], "process is not paused: no-task")

    def test_default_selection_uses_only_taxonomy_imports(self):
        adapter = self.adapter([("breakpoint", self.addresses[0], x64_regs(self.addresses[0]))])
        result = api_trace.trace(adapter, {"max_api_calls": 4})
        self.assertEqual(result["apiSet"]["selection"]["mode"], "taxonomy")
        self.assertEqual([row["name"] for row in result["apiSet"]["selected"]], ["IsDebuggerPresent"])
        self.assertEqual(result["apiSet"]["selected"][0]["category"], "debug-detection")
        self.assertEqual(len(result["calls"]), 1)

    def test_zero_iat_slot_is_unknown_not_a_breakpoint(self):
        adapter = self.adapter([], pointers=[0, self.addresses[1]])
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent", "GetTickCount64"]})
        self.assertEqual(result["apiSet"]["selectedCount"], 2)
        self.assertEqual([row["address"] for row in result["apiSet"]["breakpoints"]], [hex(self.addresses[1])])
        self.assertEqual(result["coverage"]["unresolved"][0]["api"], "IsDebuggerPresent")
        self.assertEqual(result["coverage"]["stopReason"], "process-exited")

    def test_foreign_breakpoint_stops_without_claiming_the_hit(self):
        adapter = self.adapter([("breakpoint", 0x7FF800009999, {})])
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent"]})
        self.assertEqual(result["coverage"]["stopReason"], "foreign-breakpoint")
        self.assertEqual(result["calls"], [])
        self.assertEqual(result["coverage"]["foreignStop"]["address"], "0x7ff800009999")
        self.assertTrue(result["coverage"]["breakpointCleanup"]["cleared"])

    def test_exception_stop_is_reported(self):
        adapter = self.adapter([("exception", 0, {})])
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent"]})
        self.assertEqual(result["coverage"]["stopReason"], "exception")
        self.assertEqual(result["coverage"]["foreignStop"]["data"]["ExceptionCode"], "0xc0000005")
        self.assertEqual(result["calls"], [])

    def test_unimported_request_is_disclosed_and_no_breakpoint_is_set(self):
        adapter = self.adapter([])
        result = api_trace.trace(adapter, {"api_names": ["Sleep", "NotImported"]})
        self.assertEqual(result["apiSet"]["selection"]["notImported"], ["NotImported"])
        self.assertEqual(result["apiSet"]["breakpointsSet"], 1)
        self.assertEqual(result["coverage"]["stopReason"], "process-exited")

    def test_cleanup_failure_is_not_reported_as_cleared(self):
        adapter = self.adapter([("breakpoint", self.addresses[0], x64_regs(self.addresses[0]))], clear_ok=False)
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent"], "max_api_calls": 1})
        self.assertEqual(result["coverage"]["stopReason"], "call-budget")
        self.assertFalse(result["coverage"]["breakpointCleanup"]["cleared"])
        self.assertEqual(len(result["coverage"]["breakpointCleanup"]["failures"]), 1)

    def test_cleanup_state_hiccup_keeps_observed_calls(self):
        adapter = self.adapter([("breakpoint", self.addresses[0], x64_regs(self.addresses[0]))],
                               state_raises=[RuntimeError("state rpc hiccup")])
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent"], "max_api_calls": 1})
        self.assertTrue(result["ok"])
        self.assertEqual([row["api"] for row in result["calls"]], ["IsDebuggerPresent"])
        cleanup = result["coverage"]["breakpointCleanup"]
        self.assertFalse(cleanup["attempted"])
        self.assertFalse(cleanup["cleared"])
        self.assertIn("cleanup-state-unavailable", cleanup["reason"])
        self.assertEqual(cleanup["breakpoints"], [hex(self.addresses[0])])
        self.assertEqual(result["state"], "suspended")

    def test_cancellation_during_cleanup_still_propagates(self):
        class Cancelled(Exception):
            code = "ECANCELLED"

        adapter = self.adapter([("breakpoint", self.addresses[0], x64_regs(self.addresses[0]))],
                               state_raises=[Cancelled("cancelled")])
        with self.assertRaises(Cancelled):
            api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent"], "max_api_calls": 1})

    def test_pe32_uses_stack_arguments_and_return_address(self):
        path = write(self.tmp.name, build_pe(32))
        base, esp = 0x400000, 0x600000
        memory = {base + 0x3000: (0x76540000).to_bytes(4, "little")}
        memory[esp] = (base + 0x1080).to_bytes(4, "little")
        memory[esp + 4] = (0x1).to_bytes(4, "little")
        memory[esp + 8] = (0x2).to_bytes(4, "little")
        memory[esp + 12] = (0x3).to_bytes(4, "little")
        memory[esp + 16] = (0x4).to_bytes(4, "little")
        adapter = FakeAdapter(path, 32, base, memory, [("breakpoint", 0x76540000, {"eip": 0x76540000, "esp": esp})])
        result = api_trace.trace(adapter, {"api_names": ["IsDebuggerPresent"]})
        call = result["calls"][0]
        self.assertEqual(call["arguments"]["source"], "stack-dwords")
        self.assertEqual([row["value"] for row in call["arguments"]["values"]], ["0x1", "0x2", "0x3", "0x4"])
        self.assertEqual(call["returnAddress"], hex(base + 0x1080))
        self.assertTrue(call["callerInMainModule"])

    def test_parameter_bounds_are_enforced_before_reading_imports(self):
        adapter = self.adapter([])
        for params in ({"max_api_calls": 0}, {"max_api_calls": 1025}, {"max_apis": 0}, {"max_apis": 257},
                       {"api_names": []}, {"api_names": ["A" * 65]}, {"api_names": ["ok", 3]}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                api_trace.trace(adapter, params)

    def test_requested_selection_deduplicates_aliases(self):
        adapter = self.adapter([])
        # The alias names the same import row and must not consume a second slot.
        result = api_trace.trace(adapter, {"api_names": ["Sleep", "USER32.dll!Sleep"]})
        self.assertEqual([row["name"] for row in result["apiSet"]["selected"]], ["Sleep"])
        self.assertEqual(result["apiSet"]["selectedCount"], 1)
        self.assertFalse(result["apiSet"]["selection"]["truncated"])
        self.assertEqual(result["apiSet"]["selection"]["notImported"], [])
        self.assertEqual(result["apiSet"]["breakpointsSet"], 1)

    def test_requested_selection_respects_max_apis(self):
        adapter = self.adapter([])
        result = api_trace.trace(adapter, {"api_names": ["Sleep", "IsDebuggerPresent"], "max_apis": 1})
        self.assertEqual([row["name"] for row in result["apiSet"]["selected"]], ["Sleep"])
        self.assertEqual(result["apiSet"]["selectedCount"], 1)
        self.assertTrue(result["apiSet"]["selection"]["truncated"])
        self.assertEqual(result["apiSet"]["breakpointsSet"], 1)

    def test_import_directory_past_raw_data_is_rejected(self):
        # A directory RVA inside a section's virtual size but outside its raw data has
        # no file bytes to read; the parser must refuse instead of inventing entries.
        image = bytearray(build_pe(64))
        section_table = 0x98 + 0xF0
        struct.pack_into("<I", image, section_table + 40 + 8, 0x600)    # .rdata VirtualSize 0x400 -> 0x600
        struct.pack_into("<I", image, section_table + 40 + 16, 0x400)   # .rdata SizeOfRawData stays 0x400
        struct.pack_into("<I", image, 0x98 + 112 + 8, 0x2400)           # import directory RVA -> 0x2400
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(pe_imports.ImportParseError, "unbacked"):
                pe_imports.parse_imports(write(tmp, bytes(image)))

    def test_requested_ordinal_and_module_qualified_names(self):
        adapter = self.adapter([])
        result = api_trace.trace(adapter, {"api_names": ["USER32.dll!Sleep", "#5"]})
        self.assertEqual([row["name"] for row in result["apiSet"]["selected"]], ["Sleep", "#5"])
        self.assertEqual(result["apiSet"]["selection"]["notImported"], [])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print(json.dumps({"schema": "ig5.api-trace-offline-tests.v1", "tests": result.testsRun,
                      "failures": len(result.failures), "errors": len(result.errors),
                      "skipped": len(result.skipped), "ok": result.wasSuccessful()}, sort_keys=True))
    sys.exit(0 if result.wasSuccessful() else 1)
