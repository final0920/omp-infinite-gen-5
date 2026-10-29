"""Paired catalog-based guest debugger service. Public approvals belong to DSH.

Run via the fixed GUI launcher in a locally prepared private guest bundle.
No shell, arbitrary target path, upload, IP listener or OS settings API exists.
"""
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from guest_profile import stable_read
from win_vmci import Stream, HOST, capabilities
from vmci_rpc import server_handshake, mac, verify_tag, encode
from vmci_rpc_session import serve_session

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def child_path(name):
    if not isinstance(name, str) or not name or Path(name).is_absolute() or any(part in (".", "..") for part in Path(name).parts):
        raise ValueError("Guest package path is invalid")
    file = ROOT / name
    if file.resolve() != file.absolute() or not file.is_file():
        raise ValueError("Guest package file is missing or linked")
    return file

def main():
    run = ROOT / "state" / "sessions" / uuid.uuid4().hex
    run.mkdir(parents=True)
    sys.stdout = sys.stderr = (run / "guest-service.log").open("w", encoding="utf-8", buffering=1)
    os.environ["IG5_X64DBG_STATE_ROOT"] = str(run / "debugger-state")
    service_id = uuid.uuid4().hex
    report = {"schema": "ig5-vmci-guest-service-v2", "serverInstanceId": service_id, "sessions": [], "rejectedHandshakes": [], "listenerClosed": False}
    try:
        manifest_path = ROOT / "guest-manifest.json"
        manifest = json.loads(stable_read(manifest_path, 1024*1024))
        if manifest.get("schema") != "ig5-vmci-guest-bundle-v1" or not isinstance(manifest.get("files"), list) or not 1 <= len(manifest["files"]) <= 1024:
            raise ValueError("Guest bundle manifest is invalid")
        names, total = set(), 0
        for item in manifest["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"} or item["path"] in names or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= 128*1024*1024:
                raise ValueError("Guest bundle inventory entry is invalid")
            names.add(item["path"]); total += item["bytes"]
            if total > 512*1024*1024:
                raise ValueError("Guest bundle exceeds 512 MiB")
            file = child_path(item["path"])
            if file.stat().st_size != item["bytes"] or sha(file) != item["sha256"]:
                raise ValueError("Guest bundle file digest differs: " + item["path"])
        bundle_sha = sha(manifest_path)
        key = stable_read(ROOT / "guest-pairing.key", 32)
        if len(key) != 32 or not {"guest-pairing.key", "guest-catalog.json"} <= names:
            raise ValueError("Guest key/catalog is not bound to its manifest")
        catalog = json.loads(stable_read(ROOT / "guest-catalog.json", 65536))
        if not isinstance(catalog, dict) or set(catalog) != {"schema", "port", "targets"} or catalog["schema"] != "ig5-vmci-target-catalog-v1" or type(catalog["port"]) is not int or not 1024 <= catalog["port"] <= 0xfffffffe or not isinstance(catalog["targets"], list) or not 1 <= len(catalog["targets"]) <= 64:
            raise ValueError("Invalid guest target catalog")
        targets = {}
        for target in catalog["targets"]:
            if not isinstance(target, dict) or set(target) != {"id", "path", "sha256"} or not isinstance(target["id"], str) or re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", target["id"]) is None or target["id"] in targets or target["path"] not in names:
                raise ValueError("Invalid guest target entry")
            file = child_path(target["path"])
            if file.stat().st_size > 64*1024*1024 or sha(file) != target["sha256"]:
                raise ValueError("Guest target digest/size differs")
            targets[target["id"]] = {**target, "file": file}
        caps = capabilities()
        spec = importlib.util.spec_from_file_location("ig5_guest_native_adapter", ROOT / "adapters/x64dbg/adapter.py")
        native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
        receipt_root = ROOT / "state/cleanup-receipts"
        receipt_root.mkdir(parents=True, exist_ok=True)
        if receipt_root.resolve() != receipt_root.absolute():
            raise ValueError("Guest receipt directory cannot be linked")

        class Adapter(native.Adapter):
            def __init__(self):
                self.exit_receipts, self.roots = [], {}
                self.emit_running, self.recording_window = None, False
                super().__init__(ROOT / "runtimes/x64dbg/runtime.json")
            def root_snapshot(self):
                if self.proc is not None and self.proc not in self.roots:
                    self.roots[self.proc] = {"rootId": uuid.uuid4().hex, "pid": self.proc.pid}
                return list(self.roots.values())
            def record_event(self, event):
                super().record_event(event)
                if str(event.event_type) == "EVENT_RESUME_DEBUG" and not self.recording_window and self.emit_running is not None:
                    self.emit_running({"event": dict(self.event_list()[-1])})
            def dbg(self, params):
                state = self.state()
                for expected, actual in (("expected_run_id", "runId"), ("expected_stop_seq", "stopSeq")):
                    if expected in params and params[expected] != state.get(actual):
                        raise native.RpcError("ESTALE", "Guest debugger run/pause changed", cleanedUp=False)
                if params["op"] in ("load", "start") and self.proc is None and len(self.roots) >= 256:
                    raise native.RpcError("EBUDGET", "Guest session native root limit reached")
                self.recording_window = params.get("record_trace") is True
                try: return super().dbg(params)
                finally:
                    self.root_snapshot(); self.recording_window = False
            def cleanup(self):
                process = self.proc
                self.root_snapshot()
                super().cleanup()
                if process is not None and not any(row["rootId"] == self.roots[process]["rootId"] for row in self.exit_receipts):
                    self.exit_receipts.append({**self.roots[process], "rootExitConfirmed": process.poll() is not None, "exitCode": process.returncode, "jobClosed": self.job is None})

        stopped = False
        deadline = time.monotonic()+3600
        with Stream() as listener:
            listener.bind(caps["localCID"], catalog["port"]); listener.listen()
            report.update(bundleSha256=bundle_sha, guestCID=caps["localCID"], port=catalog["port"], status="listening")
            for _ in range(64):
                if stopped: break
                stream, peer = listener.accept(deadline)
                with stream:
                    if peer["cid"] != HOST:
                        report["rejectedHandshakes"].append({"peerCID": peer["cid"]}); continue
                    try:
                        channel, _ = server_handshake(stream, key, caps["localCID"], HOST, bundle_sha, service_id, min(deadline, time.monotonic()+5))
                    except BaseException as error:
                        report["rejectedHandshakes"].append({"errorType": type(error).__name__}); continue
                    session = {"sessionId": channel.session_id, "peer": peer}
                    report["sessions"].append(session)
                    adapter, selected = Adapter(), None

                    def cleanup_proof():
                        if selected is None: return None
                        return {"schema": "ig5-guest-cleanup-v1", "guestCID": caps["localCID"], "bundleSha256": bundle_sha,
                            "serverInstanceId": service_id, "sessionId": channel.session_id, "targetId": selected["id"], "targetSha256": selected["sha256"],
                            "executionTerminal": True, "nativeRoots": list(adapter.exit_receipts),
                            "allOwnedRootsExitedAndJobsClosed": len(adapter.exit_receipts) == len(adapter.roots) and all(row["rootExitConfirmed"] and row["jobClosed"] for row in adapter.exit_receipts)}

                    def persist(proof):
                        if proof is None: return None
                        signed = {"receipt": proof, "tag": mac(key, "terminal-cleanup", proof)}
                        file = receipt_root / (channel.session_id + ".json")
                        encoded = encode(signed)
                        temporary = receipt_root / (channel.session_id + "." + uuid.uuid4().hex + ".tmp")
                        if receipt_root.resolve() != receipt_root.absolute():
                            raise ValueError("Guest receipt directory changed")
                        with temporary.open("xb") as output:
                            output.write(encoded); output.flush(); os.fsync(output.fileno())
                        os.replace(temporary, file)
                        return signed

                    def dispatch(request):
                        nonlocal selected, stopped
                        method, params = request["method"], request["params"]
                        signed = None
                        if method in ("session_close", "service_close"):
                            adapter.cleanup()
                            signed = persist(cleanup_proof())
                            result = {"ok": True, "remoteSessionClosed": True, "signedCleanup": signed}
                            stopped = method == "service_close"
                        elif method == "open":
                            if selected is not None: raise native.RpcError("ESTATE", "Guest target is already registered for this session")
                            candidate = targets.get(params["targetId"])
                            if candidate is None or sha(candidate["file"]) != candidate["sha256"]:
                                raise native.RpcError("EINVAL", "Guest target is missing or differs from its fixed catalog")
                            result = adapter.dispatch("open", {"path": str(candidate["file"])}, reset_cancel=False)
                            selected = candidate
                        elif method == "cleanup_query":
                            file = receipt_root / (params["sessionId"] + ".json")
                            try:
                                signed = json.loads(stable_read(file, 128*1024))
                                verify_tag(key, "terminal-cleanup", signed["receipt"], signed["tag"])
                            except (OSError, ValueError, KeyError) as error:
                                raise native.RpcError("ECLEANUPUNKNOWN", "Original guest cleanup receipt is unavailable; execution remains unknown") from error
                            proof = signed["receipt"]
                            if any(proof.get(key) != params[key] for key in ("serverInstanceId", "sessionId", "targetId", "targetSha256")):
                                raise native.RpcError("ECLEANUPUNKNOWN", "Original guest cleanup identity differs")
                            result = {"ok": True, "signedCleanup": signed}
                        else:
                            if method == "dbg" and selected is None: raise native.RpcError("ESTATE", "Register the fixed guest target before debugging")
                            if method == "dbg" and params["op"] in ("load", "start"):
                                if hashlib.sha256(stable_read(child_path(selected["path"]), 64*1024*1024)).hexdigest() != selected["sha256"]:
                                    raise native.RpcError("EINVAL", "Guest target bytes changed before native debugger launch")
                            result = adapter.dispatch(method, params, reset_cancel=False)
                        result["guestProvenance"] = {"transport": "paired-vmci", "guestCID": caps["localCID"], "bundleSha256": bundle_sha,
                            "serverInstanceId": service_id, "sessionId": channel.session_id,
                            "targetId": selected["id"] if selected else None, "targetSha256": selected["sha256"] if selected else None,
                            "nativeRootsObserved": adapter.root_snapshot()}
                        return result, method in ("session_close", "service_close")
                    try:
                        serve_session(adapter, channel, session, dispatch, native.RpcError, native.plain, deadline)
                    finally:
                        persist(cleanup_proof())
                        (run / "service-receipt.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        report["listenerClosed"] = True
    except BaseException as error:
        report["errorType"], report["traceback"] = type(error).__name__, traceback.format_exc()
    finally:
        report["listenerClosed"] = True
        (run / "service-receipt.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    ctypes.windll.user32.MessageBoxW(None, "Guest debugger service stopped. See its local state/session receipt.", "IG5 guest debugger", 0x10 if "errorType" in report else 0x40)

if __name__ == "__main__":
    main()
