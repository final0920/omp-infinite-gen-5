"""Bounded API-entry tracing for the owned x64dbg debuggee.

The adapter calls this only while it owns a paused native process. The module sets
software breakpoints on runtime addresses read from the main image's IAT, records
entry arguments, continues, and aggregates the observed call list. Every byte of
target execution still goes through the existing approved run/event path.

Scope: imported functions only. Dynamic resolution, delay imports, direct calls
into a DLL's code, syscalls and APIs whose IAT slot is unresolved are not observed.
Software breakpoints change API code pages in this debuggee and can be detected;
this is an analysis aid, not a stealth tracer.
"""
from __future__ import annotations

import time
from pathlib import Path
import sys

SCHEMA = "ig5.apiTrace.v1"
TRACE_VERSION = 1
DEFAULT_MAX_CALLS = 128
MAX_CALLS = 1024
DEFAULT_MAX_APIS = 64
MAX_APIS = 256
MAX_REQUESTED_NAMES = 64
MAX_NAME = 64
MAX_ARGUMENT_BYTES = 32
FATAL_CODES = frozenset({"ECANCELLED", "ETIMEDOUT", "ETRANSPORT", "EEXIT", "EJOB"})

# Breadth-first default: high-signal categories before weak/common ones.
CATEGORY_ORDER = (
    "memory-execution", "process-access", "process-enumeration", "execution", "service-driver",
    "registry", "credential-access", "privilege", "input-capture", "input-synthesis",
    "screen-capture", "hooks", "debug-detection", "file-destruction", "network", "crypto",
    "compression-codec", "dynamic-loading", "file-io", "file-enumeration", "environment-query",
)


def _load_worker(name):
    worker = Path(__file__).resolve().parents[2] / "worker"
    if str(worker) not in sys.path:
        sys.path.insert(0, str(worker))
    return __import__(name)


def _integer(value, label, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("%s must be an integer" % label)
    if not minimum <= value <= maximum:
        raise ValueError("%s must be in %d..%d" % (label, minimum, maximum))
    return value


def _requested(params):
    raw = params.get("api_names")
    if raw is None:
        return None
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_REQUESTED_NAMES:
        raise ValueError("api_names must contain 1..%d names" % MAX_REQUESTED_NAMES)
    rows = []
    for value in raw:
        if not isinstance(value, str) or not value or len(value) > MAX_NAME:
            raise ValueError("api_names entries must be non-empty strings of at most %d characters" % MAX_NAME)
        if any(ord(ch) < 0x20 or ord(ch) > 0x7e for ch in value):
            raise ValueError("api_names entries must be printable ASCII")
        rows.append(value)
    return rows


def _spec_matches(row, spec):
    if "!" in spec:
        module, name = spec.split("!", 1)
        return row["module"].lower() == module.lower() and row["name"].lower() == name.lower()
    if spec.startswith("#"):
        return row["byOrdinal"] and row["name"].lower() == spec.lower()
    return row["name"].lower() == spec.lower()


def _select(imports, params):
    requested = _requested(params)
    max_apis = _integer(params.get("max_apis", DEFAULT_MAX_APIS), "max_apis", 1, MAX_APIS)
    if requested is not None:
        rules = _load_worker("behavior_rules")
        # Match each request against the parsed import table once. Deduplicate by row
        # identity so "Sleep" and "KERNEL32.dll!Sleep" do not consume two budget slots,
        # and keep the scan linear instead of rescanning the growing selection.
        selected, missing, seen = [], [], set()
        for spec in requested:
            match = next((row for row in imports if _spec_matches(row, spec)), None)
            if match is None:
                missing.append(spec)
            elif id(match) not in seen:
                seen.add(id(match))
                selected.append({**match, "category": rules.api_category(match["name"])})
        truncated = len(selected) > max_apis
        return selected[:max_apis], {"mode": "requested", "requested": requested, "notImported": missing,
                                    "truncated": truncated}
    rules = _load_worker("behavior_rules")
    groups = {}
    for row in imports:
        category = rules.api_category(row["name"])
        if category:
            groups.setdefault(category, []).append({**row, "category": category})
    order = [name for name in CATEGORY_ORDER if name in groups] + sorted(set(groups) - set(CATEGORY_ORDER))
    queues = [sorted(groups[name], key=lambda row: (row["module"].lower(), row["name"].lower())) for name in order]
    selected = []
    while len(selected) < max_apis and any(queues):
        for queue in queues:
            if queue and len(selected) < max_apis:
                selected.append(queue.pop(0))
    return selected, {"mode": "taxonomy", "requested": [], "notImported": [],
                      "truncated": bool(any(queues)), "categories": order}


def _fatal(error):
    return getattr(error, "code", None) in FATAL_CODES


def _check(adapter):
    if hasattr(adapter, "check"):
        adapter.check()


def _state(adapter):
    return adapter.state() if hasattr(adapter, "state") else {}


def _registers(adapter):
    dump = adapter.call("get_regs")
    if hasattr(dump, "context") and hasattr(dump.context, "model_dump"):
        return dump.context.model_dump()
    if isinstance(dump, dict):
        if isinstance(dump.get("context"), dict):
            return dump["context"]
        if "regs" in dump and isinstance(dump["regs"], dict):
            return {key: int(value, 0) if isinstance(value, str) else value for key, value in dump["regs"].items()}
        return dump
    raise ValueError("register snapshot is not a mapping")


def _read(adapter, ea, size, unresolved):
    try:
        data = adapter.call("read_memory", ea, size)
    except Exception as error:
        if _fatal(error):
            raise
        unresolved.append({"ea": hex(ea), "bytes": size, "reason": str(error)[:160]})
        return None
    if not isinstance(data, (bytes, bytearray)) or len(data) != size:
        unresolved.append({"ea": hex(ea), "bytes": size,
                           "reason": "short or non-byte read (%d)" % (len(data) if isinstance(data, (bytes, bytearray)) else -1)})
        return None
    return bytes(data)


def _thread_id(adapter):
    try:
        listing = adapter.call("get_threads")
    except Exception as error:
        if _fatal(error):
            raise
        return None, "thread-list-unavailable: " + str(error)[:120]
    rows = listing.get("threads") if isinstance(listing, dict) else None
    if not isinstance(rows, list):
        return None, "thread-list-shape-unavailable"
    current = [row for row in rows if isinstance(row, dict) and row.get("current") is True]
    if len(current) != 1:
        return None, "current-thread-not-unique"
    thread = current[0].get("threadId")
    if isinstance(thread, bool) or not isinstance(thread, int) or thread <= 0:
        return None, "current-thread-id-invalid"
    return thread, "native-current-thread"


def _arguments(adapter, bits, regs, unresolved):
    if bits == 64:
        names = ("rcx", "rdx", "r8", "r9")
        values = []
        for name in names:
            value = regs.get(name)
            values.append({"name": name, "value": hex(value) if isinstance(value, int) else None})
        sp = regs.get("rsp")
        return_address = None
        if isinstance(sp, int):
            data = _read(adapter, sp, 8, unresolved)
            if data is not None:
                return_address = int.from_bytes(data, "little")
        return ({"source": "registers", "values": values}, return_address)
    esp = regs.get("esp")
    words = []
    return_address = None
    if isinstance(esp, int):
        head = _read(adapter, esp, 4, unresolved)
        if head is not None:
            return_address = int.from_bytes(head, "little")
        tail = _read(adapter, esp + 4, 16, unresolved)
        if tail is not None:
            for index in range(4):
                words.append({"name": "stack+%d" % (4 + index * 4),
                              "value": hex(int.from_bytes(tail[index * 4:index * 4 + 4], "little"))})
    return ({"source": "stack-dwords", "values": words,
             "complete": len(words) == 4}, return_address)


def _caller(adapter, bits, return_address, main_base, main_size):
    if not isinstance(return_address, int):
        return {"returnAddress": None, "callerModule": None, "callerRva": None, "callerInMainModule": None}
    row = {"returnAddress": hex(return_address), "callerModule": None, "callerRva": None,
           "callerInMainModule": False}
    if main_base <= return_address < main_base + main_size:
        row.update(callerInMainModule=True, callerRva=hex(return_address - main_base))
    else:
        try:
            info = adapter.call("module_info", return_address)
        except Exception as error:
            if _fatal(error):
                raise
            info = None
        if isinstance(info, dict) and info.get("found"):
            base = int(info["base"], 0) if isinstance(info.get("base"), str) else info.get("base")
            row.update(callerModule=info.get("name"), callerRva=hex(return_address - base) if isinstance(base, int) else None)
    return row


def _hit(adapter, bits, address, names, main_base, main_size, index, event, unresolved):
    try:
        regs = _registers(adapter)
    except Exception as error:
        if _fatal(error):
            raise
        regs, register_error = {}, str(error)[:160]
    else:
        register_error = None
    primary = names[0]
    thread, thread_source = _thread_id(adapter)
    args, return_address = _arguments(adapter, bits, regs, unresolved)
    ip_name = "rip" if bits == 64 else "eip"
    ip = regs.get(ip_name)
    row = {"index": index, "api": primary["name"], "module": primary["module"],
           "category": _load_worker("behavior_rules").api_category(primary["name"]),
           "byOrdinal": primary["byOrdinal"], "iatRva": hex(primary["iatRva"]),
           "hitAddress": hex(address), "threadId": thread, "threadSource": thread_source,
           "instructionPointer": hex(ip) if isinstance(ip, int) else None,
           "pauseMatchesHit": ip == address if isinstance(ip, int) else None,
           "arguments": args, "argumentsUnavailable": register_error,
           "argumentsScope": "raw entry values; widths and types are not recovered; return values are not observed",
           "returnAddress": None, "callerModule": None, "callerRva": None, "callerInMainModule": None,
           "breakpointHitCount": event.get("data", {}).get("hitCount") if isinstance(event.get("data"), dict) else None}
    row.update(_caller(adapter, bits, return_address, main_base, main_size))
    return row


def trace(adapter, params):
    """Run a bounded API-entry trace from the current pause and return the evidence."""
    if not isinstance(params, dict):
        raise ValueError("API trace parameters must be an object")
    max_calls = _integer(params.get("max_api_calls", DEFAULT_MAX_CALLS), "max_api_calls", 1, MAX_CALLS)
    adapter.require_pause()
    initial = adapter.context()
    if initial.get("state") != "suspended" or not initial.get("runId"):
        raise ValueError("API trace requires an identified suspended process")
    target = getattr(adapter, "target", None) or {}
    bits = target.get("bits")
    if bits not in (32, 64):
        raise ValueError("API trace requires an identified x86 or x64 target")
    if not initial.get("mainModuleBase") or not initial.get("mainModuleSize"):
        raise ValueError("main module base/size is unavailable at this pause")
    main_base, main_size = int(initial["mainModuleBase"], 16), int(initial["mainModuleSize"])
    if main_size <= 0:
        raise ValueError("main module size is unavailable")

    from pe_imports import parse_imports
    plan = parse_imports(target["path"])
    if plan["bits"] != bits:
        raise ValueError("PE file bitness differs from the loaded target")
    selected, selection = _select(plan["imports"], params)
    unresolved, set_rows, failures, address_names = [], [], [], {}
    width = 8 if bits == 64 else 4
    for row in selected:
        slot = main_base + row["iatRva"]
        data = _read(adapter, slot, width, unresolved)
        if data is None:
            continue
        address = int.from_bytes(data, "little")
        if not 0 < address < 1 << bits:
            unresolved.append({"ea": hex(slot), "bytes": width, "reason": "IAT slot is zero or outside pointer width",
                               "module": row["module"], "api": row["name"]})
            continue
        address_names.setdefault(address, []).append(row)
    for address in sorted(address_names):
        try:
            result = adapter.call("set_breakpoint", address)
        except Exception as error:
            if _fatal(error):
                raise
            failures.append({"address": hex(address), "reason": str(error)[:160],
                             "apis": [row["name"] for row in address_names[address]]})
            continue
        ok = bool(result.get("ok")) if isinstance(result, dict) else bool(result)
        set_rows.append({"address": hex(address), "apis": [row["name"] for row in address_names[address]], "ok": ok})
        if not ok:
            failures.append({"address": hex(address), "reason": "debugger rejected software breakpoint",
                             "apis": [row["name"] for row in address_names[address]]})
    live = {int(row["address"], 16) for row in set_rows if row["ok"]}
    started, calls, stop_reason, error_text, foreign = time.monotonic(), [], None, None, None
    continued = 0

    def cleanup():
        current = _state(adapter)
        if current.get("state") != "suspended":
            return {"attempted": False, "cleared": False, "reason": "process is not paused: " + str(current.get("state")),
                    "breakpoints": [hex(ea) for ea in sorted(live)]}
        cleared, problems = [], []
        for address in sorted(live):
            try:
                result = adapter.call("clear_breakpoint", address)
                ok = bool(result.get("ok")) if isinstance(result, dict) else bool(result)
            except Exception as error:
                if _fatal(error):
                    problems.append({"address": hex(address), "reason": str(error)[:160]})
                    continue
                ok = False
                problems.append({"address": hex(address), "reason": str(error)[:160]})
            if ok:
                cleared.append(hex(address))
            else:
                problems.append({"address": hex(address), "reason": "debugger rejected breakpoint clear"})
        return {"attempted": True, "cleared": len(cleared) == len(live), "clearedBreakpoints": cleared,
                "failures": problems, "breakpoints": [hex(ea) for ea in sorted(live)]}

    try:
        if not live:
            stop_reason = "no-breakpoints-set"
        while stop_reason is None and len(calls) < max_calls:
            mark = adapter.event_seq
            if not adapter.call("cmd_sync", "run"):
                stop_reason, error_text = "continuation-rejected", "debugger rejected the owned run command"
                break
            continued += 1
            waited = adapter.wait_state(mark)
            if waited.get("historyGap"):
                stop_reason = "history-gap"
                break
            if waited.get("interruptedBy"):
                stop_reason = "interrupted-" + str(waited["interruptedBy"])
                break
            if waited.get("state") == "no-task":
                stop_reason = "process-exited"
                break
            event = waited.get("event") or {}
            if not waited.get("ok"):
                stop_reason, error_text = "unconfirmed-stop", "debugger did not confirm a stop event"
                break
            if event.get("eventName") == "exception":
                stop_reason = "exception"
                foreign = {"event": "exception", "data": event.get("data"), "stopSeq": waited.get("stopSeq")}
                break
            if event.get("eventName") != "breakpoint":
                stop_reason = "stop-" + str(event.get("eventName") or "unknown")
                break
            raw_address = (event.get("data") or {}).get("addr")
            try:
                address = int(raw_address, 0) if isinstance(raw_address, str) else int(raw_address)
            except (TypeError, ValueError):
                stop_reason, error_text = "breakpoint-address-unavailable", "breakpoint event has no usable address"
                break
            if address not in live:
                stop_reason = "foreign-breakpoint"
                foreign = {"event": "breakpoint", "address": hex(address), "stopSeq": waited.get("stopSeq")}
                break
            calls.append(_hit(adapter, bits, address, address_names[address], main_base, main_size,
                              len(calls) + 1, event, unresolved))
            if len(calls) >= max_calls:
                stop_reason = "call-budget"
    finally:
        try:
            cleanup_result = cleanup()
        except Exception as error:
            # A state-read hiccup in cleanup must not erase the calls already observed.
            # Cancellation and transport loss still propagate.
            if _fatal(error):
                raise
            cleanup_result = {"attempted": False, "cleared": False,
                              "reason": "cleanup-state-unavailable: " + str(error)[:160],
                              "breakpoints": [hex(ea) for ea in sorted(live)]}

    behavior = _load_worker("api_trace_summary").summarize(calls)
    state = _state(adapter)
    observed_threads = sorted({row["threadId"] for row in calls if isinstance(row.get("threadId"), int)})
    stop_reason = stop_reason or "ended"
    return {
        "ok": stop_reason not in ("continuation-rejected", "unconfirmed-stop", "breakpoint-address-unavailable"),
        **({"error": error_text} if error_text else {}),
        "op": "apitrace", "schema": SCHEMA, "version": TRACE_VERSION,
        "evidenceLevel": "E1", "behaviorEvidenceLevel": "E0",
        "nativeTargetExecuted": continued > 0,
        "startedFrom": {"runId": initial.get("runId"), "stopSeq": initial.get("stopSeq"), "pid": initial.get("pid")},
        "runId": initial.get("runId"), "stopSeq": state.get("stopSeq"), "state": state.get("state"),
        "pid": state.get("pid"), "tid": state.get("tid"),
        "apiSet": {
            "selection": selection, "bits": bits, "importsParsed": len(plan["imports"]),
            "importModules": plan["modules"], "importTableTruncated": plan["truncated"],
            "delayImportDirectoryPresent": bool(plan.get("delayImportDirectoryRva")),
            "selected": [{"module": row["module"], "name": row["name"], "byOrdinal": row["byOrdinal"],
                          "category": row.get("category") or None} for row in selected],
            "selectedCount": len(selected), "breakpointsSet": sum(1 for row in set_rows if row["ok"]),
            "breakpoints": set_rows, "setFailures": failures,
        },
        "calls": calls,
        "behavior": behavior,
        "coverage": {
            "maxCalls": max_calls, "callsRecorded": len(calls), "callsTruncated": stop_reason == "call-budget",
            "stopReason": stop_reason, "continuations": continued, "foreignStop": foreign, "unresolved": unresolved,
            "breakpointCleanup": cleanup_result, "observedThreads": observed_threads,
            "wallMs": round((time.monotonic() - started) * 1000, 1),
            "scope": ("Only imported API entry breakpoints hit in this run. Dynamic resolution, delay imports, "
                      "direct DLL calls, syscalls and uninstrumented modules are absent; arguments are raw entry "
                      "values; return values and semantic success are not observed."),
        },
        "note": ("E1: these entries were observed by debugger breakpoints in one run. The behavior rows are E0 "
                 "leads, not intent or full coverage. Software breakpoints modify API code pages in this debuggee "
                 "and can be detected."),
    }
