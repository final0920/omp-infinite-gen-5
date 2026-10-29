"""Independent raw-recording audit of observation-local code identities, not CPU/VM proof."""
import hashlib
import json
import sys
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


root = Path(sys.argv[1]).resolve()
manifest = json.loads((root / "phase-replay.json").read_text(encoding="utf-8"))
source_bytes = Path(manifest["sourcePath"]).read_bytes()
assert digest(source_bytes) == manifest["sourceSha256"]
source = json.loads(source_bytes)
body = source["result"]
raw = Path(manifest["tracePath"]).read_bytes()
assert digest(raw) == manifest["traceSha256"] == body["sha256"]
assert not body.get("storeEvents"), "This audit explicitly covers legacy recordings without a STORE sidecar"
location = body.get("executionLocation")
location = {key: location[key] for key in ["kind", "profileSha256", "guestCID", "bundleSha256", "serverInstanceId", "sessionId"] if key in location} if location else None
fingerprint = digest(encoded(location))
points, groups, memory = {}, [], {}
epoch, changed_count = 0, 0
for line_number, text in enumerate(raw.decode("ascii").splitlines(), 1):
    fields = text.split(":")
    if fields[0] not in ["i", "c"]:
        continue
    if fields[0] == "i":
        groups.append({"pc": hex(int(fields[1], 16)), "versions": [], "changed": False})
    index = len(groups) - 1
    binding = {"targetSha256": body["targetSha256"], "runId": body["runId"], "threadId": body["threadId"],
               "runtimeBase": body["runtimeBase"], "locationFingerprint": fingerprint,
               "reportId": source["id"], "reportSha256": manifest["sourceSha256"], "traceSha256": body["sha256"],
               "groupIndex": index, "beforeStopSeq": body["startStopSeq"] + index,
               "afterStopSeq": body["startStopSeq"] + index + 1, "sourceLine": line_number,
               "pc": hex(int(fields[1], 16)), "bytes": fields[3].lower(), "beforeStateAvailable": fields[0] == "i"}
    code = bytes.fromhex(binding["bytes"])
    assert len(code) == int(fields[2])
    version_id = digest(encoded(binding))
    changed = []
    for offset, value in enumerate(code):
        address = int(binding["pc"], 16) + offset
        prior = memory.get(address)
        if prior and prior[0] != value:
            changed.append({"address": hex(address), "before": f"{prior[0]:02x}", "after": f"{value:02x}", "priorVersionId": prior[1]})
            changed_count += 1
        if prior or len(memory) < 16384:
            memory[address] = (value, version_id)
    if changed:
        epoch += 1
        groups[index]["changed"] = True
    expected = {"id": version_id, "binding": binding, "contentSha256": digest(code)}
    points[line_number] = (expected, epoch, changed)
    groups[index]["versions"].append(line_number)
assert len(groups) == body.get("confirmedStepStops", body["instructionCount"])
seen = set()
for group in groups:
    group["revisited"] = group["pc"] in seen
    seen.add(group["pc"])
verified = 0
for path_key, sha_key in [("fullReportPath", "fullReportSha256"), ("overlapReportPath", "overlapReportSha256")]:
    raw_result = Path(manifest[path_key]).read_bytes()
    assert digest(raw_result) == manifest[sha_key]
    result = json.loads(raw_result)["result"]
    model = result["phaseModel"]
    assert model["counts"]["groups"] == len(groups)
    assert model["counts"]["revisits"] == sum(g["revisited"] for g in groups)
    assert model["counts"]["missingStoreGroups"] == len(groups)
    assert model["counts"]["codeChangeGroups"] == sum(g["changed"] for g in groups)
    assert model["codeEpochs"]["observedChangedBytes"] == changed_count
    assert model["codeEpochs"]["observationEpoch"] == epoch
    assert model["codeEpochs"]["globalCodeEpochKnown"] is False
    assert model["phaseVerified"] is False and model["smcCoverageComplete"] is False
    for group in model["groups"]:
        original = groups[group["groupIndex"]]
        assert group["phase"] == "unknown" and group["verifiedPhase"] is None
        assert group["events"]["unknownStores"] is None
        assert group["events"]["controlVisit"] == ("revisited" if original["revisited"] else "first-observed")
        for row, line in zip(group["versions"], original["versions"], strict=True):
            expected, expected_epoch, changed = points[line]
            assert all(row["version"][key] == value for key, value in expected.items())
            assert row["version"]["validBetweenObservations"] is False
            assert row["relation"]["observationEpoch"] == expected_epoch
            assert row["relation"]["changedBytes"] == changed
            assert row["relation"]["intervalStable"] == "unknown"
            verified += 1
audit = {"schema": "ig5-vm-phase-raw-audit-v1", "ok": True, "sourceSha256": manifest["sourceSha256"],
         "traceSha256": manifest["traceSha256"], "auditorSha256": digest(Path(__file__).read_bytes()),
         "sourceGroups": len(groups), "pointVersionsVerified": verified, "observedChangedBytes": changed_count,
         "scope": "Independent raw-byte/source/point identity recomputation; no CPU, VM-stage, write causality or SMC completeness proof"}
(root / "raw-audit.json").write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
print(json.dumps(audit))
