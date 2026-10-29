"""Internal host stdio bridge to a paired, catalog-based guest debugger.

The DSH tool gate owns approvals. This adapter is not a user execution CLI.
Host process/pipe exit never reports that a guest execution was cleaned up.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
from guest_profile import load_profile, stable_read
from host_rpc_client import Client, RemoteError
from vmci_rpc import ProtocolError, verify_tag

class BridgeError(ValueError):
    pass

def inspect_target(filename):
    path = Path(filename)
    data = stable_read(path, 64*1024*1024)
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise BridgeError("Guest target must be an AMD64 or x86 PE")
    offset = struct.unpack_from("<I", data, 0x3c)[0]
    if offset > 0x100000 or offset+0x60 > len(data) or data[offset:offset+4] != b"PE\0\0":
        raise BridgeError("Guest target PE header is invalid")
    machine, magic = struct.unpack_from("<H", data, offset+4)[0], struct.unpack_from("<H", data, offset+24)[0]
    bits = {0x8664: 64, 0x14c: 32}.get(machine)
    if bits is None or magic != (0x20b if bits == 64 else 0x10b):
        raise BridgeError("Guest target PE architecture differs")
    base = struct.unpack_from("<Q" if bits == 64 else "<I", data, offset+(48 if bits == 64 else 52))[0]
    return {"path": str(path), "bits": bits, "databaseBase": hex(base), "entryRVA": hex(struct.unpack_from("<I", data, offset+40)[0]), "sha256": hashlib.sha256(data).hexdigest()}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--profile-sha256", required=True)
    args = parser.parse_args()
    sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    sys.stdout.reconfigure(encoding="utf-8", errors="strict", line_buffering=True)
    protocol = os.fdopen(os.dup(sys.stdout.fileno()), "w", encoding="utf-8", buffering=1)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno()); sys.stdout = sys.stderr
    output_lock, pending_lock = threading.Lock(), threading.Lock()
    pending, threads = {}, set()
    target = None
    closed = False

    def send(value):
        data = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(data.encode("utf-8")) > 16*1024*1024:
            raise BridgeError("Guest worker output exceeds 16 MiB")
        with output_lock:
            protocol.write(data+"\n")

    profile, key = load_profile(args.profile, args.profile_sha256)
    client = Client(profile["guestCID"], profile["port"], key, profile["bundleSha256"], None)
    identity = {"kind": "vmci-guest", "profileSha256": args.profile_sha256, "guestCID": profile["guestCID"],
        "bundleSha256": profile["bundleSha256"], "serverInstanceId": client.hello["serverInstanceId"], "sessionId": client.channel.session_id}

    def convert(result):
        result = dict(result)
        provenance = result.get("guestProvenance")
        if provenance is not None:
            if any(provenance.get(name) != identity[name] for name in ("guestCID", "bundleSha256", "serverInstanceId", "sessionId")):
                raise ProtocolError("Guest result provenance differs from the paired connection")
            if target is not None and provenance.get("targetSha256") not in (None, target["sha256"]):
                raise ProtocolError("Guest result target differs")
        signed = result.pop("signedCleanup", None)
        if signed is not None:
            if not isinstance(signed, dict) or set(signed) != {"receipt", "tag"}:
                raise ProtocolError("Guest signed cleanup envelope differs")
            verify_tag(key, "terminal-cleanup", signed["receipt"], signed["tag"])
            result["guestCleanup"] = signed["receipt"]
            result["guestCleanupHMACVerified"] = True
        result["executionLocation"] = identity
        result["authenticatedGuestResponse"] = True
        return result

    def invoke(ident, method, params):
        nonlocal target, closed
        try:
            if closed: raise BridgeError("Guest bridge session is closed")
            if method == "open":
                inspected = inspect_target(params.get("path") or params.get("target"))
                matches = [row for row in profile["targets"] if row["sha256"] == inspected["sha256"]]
                if len(matches) != 1 or target is not None: raise BridgeError("Opened artifact is absent/ambiguous in the guest catalog, or session already has a target")
                target = {**inspected, "targetId": matches[0]["id"]}
                remote_method, remote_params = "open", {"targetId": matches[0]["id"]}
            elif method == "dbg":
                if target is None: raise BridgeError("Register the host/guest target before debugging")
                if params.get("path"):
                    if inspect_target(params["path"])["sha256"] != target["sha256"]: raise BridgeError("Guest start path differs from the opened artifact")
                omitted = {"backend", "control", "path", "trace_inputs", "trace_output", "guest_profile", "guest_binding_sha256"}
                remote_params = {key: value for key, value in params.items() if key not in omitted and value is not None and value != ""}
                for field in ("ea", "rva", "value", "until"):
                    if field in remote_params: remote_params[field] = hex(int(str(remote_params[field]), 0))
                if "expected" in remote_params and params.get("op") == "setreg": remote_params["expected"] = hex(int(str(remote_params["expected"]), 0))
                remote_method = "dbg"
            elif method == "close":
                remote_method, remote_params = "session_close", {}
            elif method == "recover":
                if target is not None: raise BridgeError("Recovery requires a fresh metadata-only guest connection")
                remote_method, remote_params = "cleanup_query", params
                if not any(row["id"] == params.get("targetId") and row["sha256"] == params.get("targetSha256") for row in profile["targets"]):
                    raise BridgeError("Recovery target differs from its fixed profile catalog")
            elif method == "doctor":
                remote_method, remote_params = "doctor", {}
            else: raise BridgeError("Unknown guest adapter method")
            with pending_lock:
                entry = pending[ident]
                if entry["cancelled"]:
                    send({"id": ident, "error": {"code": "ECANCELLED", "message": "Guest request cancelled before dispatch", "cancelledBeforeExecution": True, "cleanedUp": False}})
                    return
                remote_id, future = client.begin(remote_method, remote_params)
                entry["remoteId"] = remote_id
            result = convert(future.result(timeout=140))
            if method == "open":
                if result.get("guestProvenance", {}).get("targetSha256") != target["sha256"]: raise ProtocolError("Guest catalog target digest differs")
                result["hostTarget"] = dict(target)
            if method == "close":
                # No response is required for this final one-way ACK. The
                # already authenticated terminal receipt remains authoritative
                # even if delivery of this housekeeping message fails.
                with contextlib.suppress(OSError, ValueError, RuntimeError): client.begin("close_ack", {})
                closed = True
            send({"id": ident, "result": result})
        except RemoteError as error:
            send({"id": ident, "error": {**error.detail, "executionLocation": identity, "authenticatedGuestResponse": True}})
        except (ValueError, KeyError, TypeError, OSError, TimeoutError) as error:
            send({"id": ident, "error": {"code": "ETRANSPORT" if isinstance(error, (ProtocolError, OSError, TimeoutError)) else "EINVAL", "message": str(error), "executionLocation": identity, "guestCleanupConfirmed": False}})
        except BaseException as error:
            send({"id": ident, "error": {"code": "EBACKEND", "message": type(error).__name__, "executionLocation": identity, "guestCleanupConfirmed": False}})
        finally:
            with pending_lock:
                pending.pop(ident, None); threads.discard(threading.current_thread())

    send({"ig5": "ready", "engine": "x64dbg", "capabilities": ["doctor", "open", "dbg", "close", "recover", "cancel"], "executionLocation": identity})
    try:
        for line in sys.stdin:
            request = None
            try:
                if len(line.encode("utf-8")) > 65536: raise BridgeError("Guest worker request exceeds 64 KiB")
                request = json.loads(line)
                if not isinstance(request, dict) or type(request.get("id")) is not int or not 1 <= request["id"] < 2**31 or not isinstance(request.get("method"), str) or not isinstance(request.get("params"), dict):
                    raise BridgeError("Guest worker requires typed id/method/params")
                ident, method, params = request["id"], request["method"], request["params"]
                if method == "cancel":
                    with pending_lock:
                        entry = pending.get(params.get("requestId"))
                        if entry is not None: entry["cancelled"] = True
                        remote_id = entry["remoteId"] if entry else None
                    if remote_id is not None:
                        _, future = client.begin("cancel", {"requestId": remote_id})
                        def cancelled(value, ident=ident):
                            try: send({"id": ident, "result": value.result()})
                            except BaseException: pass
                        future.add_done_callback(cancelled)
                    else: send({"id": ident, "result": {"ok": True, "cancelRequested": entry is not None, "queued": entry is not None}})
                    continue
                with pending_lock:
                    if ident in pending or len(pending) >= 64: raise BridgeError("Guest worker request id/queue limit exceeded")
                    pending[ident] = {"remoteId": None, "cancelled": False}
                    thread = threading.Thread(target=invoke, args=(ident, method, params), daemon=True)
                    threads.add(thread)
                thread.start()
            except BaseException as error:
                send({"id": request.get("id") if isinstance(request, dict) else None, "error": {"code": "EPROTOCOL", "message": str(error)}})
    finally:
        client.close()
        with pending_lock: active = list(threads)
        for thread in active: thread.join(timeout=2)

if __name__ == "__main__":
    main()
