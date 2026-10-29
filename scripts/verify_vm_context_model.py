#!/usr/bin/env python3
"""Independent byte/hash and semantic-shape audit for a VM context report."""
from __future__ import annotations
import hashlib
import json
import os
import re
import sys

GPRS = "rax rbx rcx rdx rdi rsi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15".split()
SHA = re.compile(r"^[0-9a-f]{64}$")
UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")

def reject(message: str) -> None:
    raise ValueError("VM context audit: " + message)

def read_json(filename: str, expected_sha: str, maximum: int = 8 * 1024 * 1024):
    if not os.path.isabs(filename) or not SHA.fullmatch(expected_sha or ""):
        reject("absolute path and lowercase SHA-256 required")
    before = os.stat(filename, follow_symlinks=False)
    if not os.path.isfile(filename) or os.path.islink(filename) or before.st_size > maximum:
        reject("source must be a bounded regular non-link file")
    with open(filename, "rb") as stream:
        data = stream.read(maximum + 1)
    after = os.stat(filename, follow_symlinks=False)
    if len(data) > maximum or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        reject("source changed or exceeded budget")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha:
        reject("SHA-256 mismatch for " + filename)
    return json.loads(data.decode("utf-8")), len(data), actual

def exact_ref(ref):
    return isinstance(ref, dict) and UUID.fullmatch(ref.get("id", "")) and SHA.fullmatch(ref.get("sha256", "")) and os.path.isabs(ref.get("path", ""))

def count_candidates(rows, total, excluded=()):
    return sorted(name for name, count in rows.items() if count == total and name not in excluded)

def audit(report_path: str, report_sha: str):
    report, report_bytes, actual_sha = read_json(os.path.abspath(report_path), report_sha, 4 * 1024 * 1024)
    if report.get("kind") != "vm-context-model" or report.get("action") != "derive" or not UUID.fullmatch(report.get("id", "")):
        reject("report identity differs")
    result = report.get("result")
    if not isinstance(result, dict) or result.get("schema") != "ig5-vm-context-model-v1" or result.get("status") != "single-run-context-candidates-phases-unknown":
        reject("report schema/status differs")
    source_groups = result.get("sourceReports")
    if not isinstance(source_groups, list) or not 1 <= len(source_groups) <= 16:
        reject("source report groups differ")
    fetch, indexed, opcode, target = {}, {}, {}, {}
    dictionary, occurrence_keys, targets, recordings = [], set(), set(), set()
    ordinary = partial = unknown_gprs = unknown_stores = total = 0
    stack = {name: {"name": name, "bodies": 0, "mutatedBodies": 0, "smallAlignedDeltaBodies": 0,
                    "nearbyAccessBodies": 0, "nearbyAccesses": 0, "deltaExamples": []} for name in GPRS}
    mask = (1 << 64) - 1
    def distance(a, b):
        value = (int(b, 16) - int(a, 16)) & mask
        return value - (1 << 64) if value > (1 << 63) else value
    source_files = 0
    for group in source_groups:
        if not isinstance(group, dict) or set(group) != {"handlers", "recurrence", "selection"} or not all(exact_ref(group[key]) for key in group):
            reject("source reference shape differs")
        loaded = {}
        for key, kind, action in (("handlers", "vm-recorded-handlers", "assess"), ("recurrence", "vm-flow-recurrences", "validate"), ("selection", "vm-handler-windows", "select")):
            record, _, _ = read_json(group[key]["path"], group[key]["sha256"])
            source_files += 1
            if record.get("id") != group[key]["id"] or record.get("kind") != kind or record.get("action") != action:
                reject("source record identity differs")
            loaded[key] = record.get("result")
        handlers, recurrence, selection = loaded["handlers"], loaded["recurrence"], loaded["selection"]
        if handlers.get("schema") != "ig5-recorded-handlers-v1" or recurrence.get("schema") != "ig5-flow-recurrences-v1" or selection.get("schema") != "ig5-recorded-handler-windows-v1":
            reject("source schemas differ")
        if handlers.get("sourceRecurrence", {}).get("id") != group["recurrence"]["id"] or handlers.get("sourceRecurrence", {}).get("sha256") != group["recurrence"]["sha256"]:
            reject("recurrence binding differs")
        if handlers.get("sourceSelection", {}).get("id") != group["selection"]["id"] or handlers.get("sourceSelection", {}).get("sha256") != group["selection"]["sha256"]:
            reject("selection binding differs")
        target_sha = handlers.get("targetSha256")
        if target_sha != recurrence.get("targetSha256") or target_sha != selection.get("targetSha256") or not SHA.fullmatch(target_sha or ""):
            reject("target identity differs")
        targets.add(target_sha)
        hs, rs, ss = handlers.get("bodies"), recurrence.get("occurrences"), selection.get("bodies")
        if not isinstance(hs, list) or not isinstance(rs, list) or not isinstance(ss, list) or len(hs) != len(rs) or len(hs) != len(ss) or len(hs) > 8:
            reject("source body counts differ")
        if recurrence.get("distinctRecordedRuns") != 1 or handlers.get("vmRoleProved") is not False or recurrence.get("vmRoleProved") is not False:
            reject("source scope differs")
        for h, r, s in zip(hs, rs, ss):
            if h.get("sourceOccurrence") != r.get("startGroup") or h.get("sourceOccurrence") != s.get("sourceOccurrence") or h.get("sourceValue") != r.get("sourceValue") or h.get("sourceValue") != s.get("sourceValue") or h.get("observedEntry") != r.get("target") or h.get("observedEntry") != s.get("observedEntry"):
                reject("source body binding differs")
            status = h.get("status")
            if status not in ("consistent-recorded-ordinary-state", "partially-consistent-unknown-preserved") or h.get("assessment", {}).get("status") != status:
                reject("source status differs")
            key = (r.get("firstRecordingId"), r.get("startGroup"))
            if key in occurrence_keys:
                reject("duplicate occurrence")
            occurrence_keys.add(key); recordings.update((r.get("firstRecordingId"), r.get("lastRecordingId"))); total += 1
            for update in r.get("sourceAddressInputUpdates", []):
                name, observed_delta = update.get("name"), update.get("deltaModulo64")
                if name not in GPRS:
                    reject("invalid fetch input")
                fetch[(name, observed_delta)] = fetch.get((name, observed_delta), 0) + 1
            for indexed_read in r.get("indexedAddressInputValues", []):
                for item in indexed_read.get("inputs", []):
                    name = item.get("name")
                    if name not in GPRS:
                        reject("invalid indexed input")
                    indexed[name] = indexed.get(name, 0) + 1
            for name in GPRS:
                if r.get("finalGprs", {}).get(name) == r.get("sourceValue"):
                    opcode[name] = opcode.get(name, 0) + 1
                if r.get("finalGprs", {}).get(name) == r.get("target"):
                    target[name] = target.get(name, 0) + 1
            groups = s.get("groups")
            if not isinstance(groups, list) or not 1 <= len(groups) <= 128:
                reject("selected group budget differs")
            accesses = []
            for observed in groups:
                reads = observed.get("memoryReads", [])
                writes = observed.get("memoryWrites", [])
                if isinstance(reads, list): accesses.extend(reads)
                if isinstance(writes, dict): writes = writes.get("stores", [])
                if isinstance(writes, list): accesses.extend(writes)
            if len(accesses) > 4096: reject("memory access budget differs")
            for name in GPRS:
                before = groups[0]["before"]["gprs"][name]
                after = groups[-1]["after"]["gprs"][name]
                if any(not isinstance(v, str) or re.fullmatch(r"0x[0-9a-f]{1,16}", v) is None for v in (before, after)):
                    reject("unobserved register")
                nearby = sum(isinstance(a.get("address"), str) and re.fullmatch(r"0x[0-9a-f]{1,16}", a["address"]) is not None
                             and any(-4096 <= distance(base, a["address"]) <= 4096 for base in (before, after)) for a in accesses)
                row = stack[name]; row["bodies"] += 1; row["nearbyAccesses"] += nearby
                if nearby: row["nearbyAccessBodies"] += 1
                if before != after:
                    row["mutatedBodies"] += 1
                    delta = hex((int(after, 16) - int(before, 16)) & mask)
                    signed = distance(before, after)
                    if -256 <= signed <= 256 and signed % 2 == 0: row["smallAlignedDeltaBodies"] += 1
                    if len(row["deltaExamples"]) < 8 and delta not in row["deltaExamples"]: row["deltaExamples"].append(delta)
            assessment = h.get("assessment", {})
            gprs = assessment.get("gprs")
            if not isinstance(gprs, list) or [item.get("name") for item in gprs] != GPRS:
                reject("GPR assessment differs")
            ug = [item["name"] for item in gprs if item.get("status") == "unknown-preserved"]
            stores = assessment.get("orderedStores", [])
            us = sum(item.get("valueStatus") == "unknown-preserved" for item in stores)
            ordinary += status == "consistent-recorded-ordinary-state"; partial += status == "partially-consistent-unknown-preserved"
            unknown_gprs += len(ug); unknown_stores += us
            dictionary.append({"sourceValue": h.get("sourceValue"), "observedEntry": h.get("observedEntry"), "sourceOccurrence": h.get("sourceOccurrence"),
                "status": status, "projection": h.get("projection"), "matchedFinalGprs": 16 - len(ug), "unknownGprs": ug,
                "orderedStores": len(stores), "unknownStores": us, "terminalControl": assessment.get("control"),
                "semanticOpcodeLabel": None, "instructionSemanticsProved": False})
    if len(targets) != 1 or result.get("targetSha256") not in targets:
        reject("mixed or wrong targets")
    evidence = result.get("evidence", {})
    expected_evidence = {"sourcePages": len(source_groups), "occurrences": total, "distinctRecordingIds": len(recordings), "recordingIds": sorted(recordings),
        "ordinaryConsistent": ordinary, "partialUnknownPreserved": partial, "unverified": 0,
        "unknownGprResults": unknown_gprs, "unknownStoreValues": unknown_stores}
    if evidence != expected_evidence:
        reject("evidence counts differ")
    roles = result.get("roles", {})
    expected_vsp = sorted((dict(row, coverage=f'{row["nearbyAccessBodies"]}/{total}',
                                    kind="memory-proximate-mutable-register", vmRoleProved=False)
                           for row in stack.values() if row["nearbyAccessBodies"] > 0 and row["mutatedBodies"] > 0),
                          key=lambda row: (-row["nearbyAccessBodies"], -row["smallAlignedDeltaBodies"], row["name"]))
    if json.dumps(roles.get("vspCandidates"), sort_keys=True) != json.dumps(expected_vsp, sort_keys=True): reject("VSP candidate derivation differs")
    for family in ("vipCandidates", "dispatchBaseCandidates", "opcodeCarrierCandidates", "handlerTargetCarrierCandidates", "vspCandidates"):
        if not isinstance(roles.get(family), list) or any(row.get("vmRoleProved") is not False for row in roles[family]):
            reject("candidate proof boundary differs")
    vip = count_candidates({name + ":" + observed_delta: count for (name, observed_delta), count in fetch.items()}, total)
    vip_names = sorted(item.split(":", 1)[0] for item in vip)
    if sorted(item.get("name") for item in roles.get("vipCandidates", [])) != vip_names:
        reject("VIP candidates differ")
    if sorted(item.get("name") for item in roles.get("dispatchBaseCandidates", [])) != count_candidates(indexed, total, vip_names):
        reject("dispatch base candidates differ")
    if sorted(item.get("name") for item in roles.get("opcodeCarrierCandidates", [])) != count_candidates(opcode, total):
        reject("opcode carriers differ")
    if sorted(item.get("name") for item in roles.get("handlerTargetCarrierCandidates", [])) != count_candidates(target, total):
        reject("target carriers differ")
    if roles.get("genericMappingProved") is not False or roles.get("competingCandidatesRetained") is not True:
        reject("role proof boundary differs")
    if result.get("observedHandlerDictionary") != sorted(dictionary, key=lambda item: item["sourceOccurrence"]):
        reject("handler dictionary differs")
    phases = result.get("phases", {})
    if phases.get("initialization", {}).get("status") != "unknown" or phases.get("fixup", {}).get("status") != "unknown" or phases.get("businessExecution", {}).get("status") != "unknown" or phases.get("dispatchExecution", {}).get("status") != "observed-candidate" or phases.get("phaseClassificationProved") is not False or phases.get("moduleLoadEpoch") is not None or phases.get("memoryEpoch") is not None:
        reject("phase boundaries differ")
    for key in ("nativeTargetExecuted", "changesExecutionAuthority", "databaseModified", "instructionSemanticsProved", "vmRoleProved", "vmIsaProved", "concreteBytecodeProgramRecovered", "wholeVmRecovered", "independentInputCoverageProved", "businessAccepted", "wholeFunctionCoverageProved", "wholeBinaryVerified"):
        if result.get(key) is not False:
            reject("false scope flag upgraded: " + key)
    return {"schema": "ig5-vm-context-independent-audit-v1", "passed": True, "reportPath": os.path.abspath(report_path),
        "reportBytes": report_bytes, "reportSha256": actual_sha, "sourceFiles": source_files,
        "sourcePages": len(source_groups), "occurrences": total, "ordinaryConsistent": ordinary,
        "partialUnknownPreserved": partial, "vipCandidates": vip_names,
        "dispatchBaseCandidates": count_candidates(indexed, total, vip_names), "businessAccepted": False}

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: verify_vm_context_model.py REPORT_PATH REPORT_SHA256", file=sys.stderr)
        raise SystemExit(2)
    try:
        print(json.dumps(audit(sys.argv[1], sys.argv[2]), separators=(",", ":"), sort_keys=True))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
