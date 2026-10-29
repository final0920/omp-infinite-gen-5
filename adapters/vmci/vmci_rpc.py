"""Bounded authenticated guest debugger RPC; no target or OS operations here.

HMAC possession authenticates the lab pairing key, not a trusted guest process.
The guest OS and all processes able to read the key remain inside the trust base.
"""
import hashlib
import hmac
import json
import re
import secrets
import struct
import threading
import time

VERSION = "ig5-vmci-debug-rpc-v2"
MAX_REQUEST = 16384
MAX_RESULT = 16 * 1024 * 1024
MAX_MESSAGES = 1024
MAX_DEPTH = 32
MAX_NODES = 262144

class ProtocolError(ValueError):
    pass

def encode(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_NODES or isinstance(item, (dict, list)) and depth >= MAX_DEPTH:
            raise ProtocolError("RPC depth/node budget exceeded")
        if isinstance(item, dict):
            if not all(isinstance(key, str) for key in item):
                raise ProtocolError("RPC object keys must be strings")
            stack.extend((entry, depth + 1) for entry in item.values())
        elif isinstance(item, list):
            stack.extend((entry, depth + 1) for entry in item)
        elif isinstance(item, str) and len(item) > MAX_RESULT:
            raise ProtocolError("RPC string budget exceeded")
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (ValueError, TypeError, RecursionError) as error:
        raise ProtocolError("Noncanonical RPC data") from error

def pairs(items):
    value = {}
    for key, entry in items:
        if key in value:
            raise ProtocolError("Duplicate RPC key")
        value[key] = entry
    return value

def decode(data):
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                raise ProtocolError("RPC depth budget exceeded before JSON parsing")
        elif byte in (93, 125):
            depth -= 1
    try:
        value = json.loads(data.decode("ascii"), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError("Nonfinite RPC number")))
        if encode(value) != data:
            raise ProtocolError("RPC encoding is not canonical")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProtocolError("Invalid RPC JSON") from error

def exact(stream, size, deadline):
    output = bytearray()
    while len(output) < size:
        output.extend(stream.receive(min(65536, size - len(output)), deadline))
    return bytes(output)

def send_plain(stream, value, maximum, deadline):
    data = encode(value)
    if not 1 <= len(data) <= maximum:
        raise ProtocolError("RPC frame size exceeds budget")
    stream.send(struct.pack("<I", len(data)), deadline)
    for offset in range(0, len(data), 32768):
        stream.send(data[offset:offset + 32768], deadline)

def receive_plain(stream, maximum, deadline):
    size = struct.unpack("<I", exact(stream, 4, deadline))[0]
    if not 1 <= size <= maximum:
        raise ProtocolError("RPC frame size exceeds budget")
    return decode(exact(stream, size, deadline))

def mac(key, domain, value):
    return hmac.new(key, domain.encode("ascii") + b"\0" + encode(value), hashlib.sha256).hexdigest()

def verify_tag(key, domain, value, tag):
    if not isinstance(tag, str) or re.fullmatch("[0-9a-f]{64}", tag) is None or not hmac.compare_digest(mac(key, domain, value), tag):
        raise ProtocolError("RPC authentication failed")

def check_key(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ProtocolError("RPC pairing key must be 32 bytes")

def session_material(key, hello, client_nonce):
    transcript = {"hello": hello, "clientNonce": client_nonce}
    session_id = hashlib.sha256(encode(transcript)).hexdigest()
    session_key = bytes.fromhex(mac(key, "session-key", transcript))
    return session_id, session_key

def server_handshake(stream, key, server_cid, client_cid, bundle_hash, server_instance, deadline):
    check_key(key)
    if not isinstance(bundle_hash, str) or re.fullmatch("[0-9a-f]{64}", bundle_hash) is None:
        raise ProtocolError("RPC bundle digest missing")
    if not isinstance(server_instance, str) or re.fullmatch("[0-9a-f]{32}", server_instance) is None:
        raise ProtocolError("RPC server instance missing")
    hello = {"version": VERSION, "serverCID": server_cid, "clientCID": client_cid, "serverInstanceId": server_instance,
        "serverNonce": secrets.token_hex(32), "bundleSha256": bundle_hash}
    send_plain(stream, {"hello": hello, "tag": mac(key, "server-hello", hello)}, 4096, deadline)
    proof = receive_plain(stream, 4096, deadline)
    if not isinstance(proof, dict) or set(proof) != {"clientNonce", "tag"} or not isinstance(proof["clientNonce"], str) or re.fullmatch("[0-9a-f]{64}", proof["clientNonce"]) is None:
        raise ProtocolError("Invalid RPC client proof")
    transcript = {"hello": hello, "clientNonce": proof["clientNonce"]}
    verify_tag(key, "client-proof", transcript, proof["tag"])
    session_id, session_key = session_material(key, hello, proof["clientNonce"])
    ready = {"version": VERSION, "session": session_id}
    send_plain(stream, {**ready, "tag": mac(session_key, "server-ready", ready)}, 4096, deadline)
    return Channel(stream, session_id, session_key, server=True), hello

def client_handshake(stream, key, server_cid, client_cid, bundle_hash, deadline):
    check_key(key)
    packet = receive_plain(stream, 4096, deadline)
    if not isinstance(packet, dict) or set(packet) != {"hello", "tag"} or not isinstance(packet["hello"], dict):
        raise ProtocolError("Invalid RPC server hello")
    hello = packet["hello"]
    if set(hello) != {"version", "serverCID", "clientCID", "serverNonce", "bundleSha256", "serverInstanceId"} or hello["version"] != VERSION or type(hello["serverCID"]) is not int or type(hello["clientCID"]) is not int or hello["serverCID"] != server_cid or hello["clientCID"] != client_cid or hello["bundleSha256"] != bundle_hash or not isinstance(hello["serverNonce"], str) or re.fullmatch("[0-9a-f]{64}", hello["serverNonce"]) is None or not isinstance(hello["serverInstanceId"], str) or re.fullmatch("[0-9a-f]{32}", hello["serverInstanceId"]) is None:
        raise ProtocolError("RPC peer/bundle identity differs")
    verify_tag(key, "server-hello", hello, packet["tag"])
    nonce = secrets.token_hex(32)
    transcript = {"hello": hello, "clientNonce": nonce}
    send_plain(stream, {"clientNonce": nonce, "tag": mac(key, "client-proof", transcript)}, 4096, deadline)
    session_id, session_key = session_material(key, hello, nonce)
    ready = receive_plain(stream, 4096, deadline)
    if not isinstance(ready, dict) or set(ready) != {"version", "session", "tag"} or ready["version"] != VERSION or ready["session"] != session_id:
        raise ProtocolError("RPC ready identity differs")
    verify_tag(session_key, "server-ready", {"version": VERSION, "session": session_id}, ready["tag"])
    return Channel(stream, session_id, session_key, server=False), hello

class Channel:
    def __init__(self, stream, session_id, session_key, server):
        self.stream, self.session_id, self.key = stream, session_id, session_key
        self.server = server
        self.send_sequence, self.receive_sequence = 0, 0
        self.send_lock = threading.Lock()
        self.failed = False

    def send(self, message, deadline):
        with self.send_lock:
            if self.failed or self.send_sequence >= MAX_MESSAGES:
                raise ProtocolError("RPC channel closed or message budget exceeded")
            envelope = {"version": VERSION, "session": self.session_id, "seq": self.send_sequence + 1, "message": message}
            envelope["tag"] = mac(self.key, "server-result" if self.server else "client-request", envelope)
            try:
                send_plain(self.stream, envelope, MAX_RESULT if self.server else MAX_REQUEST, deadline)
            except BaseException:
                self.failed = True
                self.stream.close()
                raise
            self.send_sequence += 1

    def receive(self, deadline):
        if self.failed or self.receive_sequence >= MAX_MESSAGES:
            raise ProtocolError("RPC channel closed or message budget exceeded")
        try:
            envelope = receive_plain(self.stream, MAX_REQUEST if self.server else MAX_RESULT, deadline)
            if not isinstance(envelope, dict) or set(envelope) != {"version", "session", "seq", "message", "tag"} or envelope["version"] != VERSION or envelope["session"] != self.session_id or type(envelope["seq"]) is not int or envelope["seq"] != self.receive_sequence + 1:
                raise ProtocolError("RPC session or sequence differs")
            tag = envelope.pop("tag")
            verify_tag(self.key, "client-request" if self.server else "server-result", envelope, tag)
            self.receive_sequence += 1
            return envelope["message"]
        except BaseException:
            self.failed = True
            self.stream.close()
            raise

def validate_request(value):
    if not isinstance(value, dict) or set(value) != {"id", "method", "params"} or type(value["id"]) is not int or not 1 <= value["id"] < 2**31 or not isinstance(value["params"], dict):
        raise ProtocolError("RPC requires a positive integer id, typed method and object params")
    method, params = value["method"], value["params"]
    if method in ("doctor", "close", "session_close", "service_close", "close_ack"):
        if params:
            raise ProtocolError("RPC method takes no parameters")
    elif method == "open":
        if set(params) != {"targetId"} or not isinstance(params["targetId"], str) or re.fullmatch("[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", params["targetId"]) is None:
            raise ProtocolError("RPC target requires an explicit catalog ID")
    elif method == "cleanup_query":
        if set(params) != {"serverInstanceId", "sessionId", "targetId", "targetSha256"} or any(not isinstance(params[key], str) or re.fullmatch(pattern, params[key]) is None for key, pattern in (("serverInstanceId", "[0-9a-f]{32}"), ("sessionId", "[0-9a-f]{64}"), ("targetSha256", "[0-9a-f]{64}"), ("targetId", "[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"))):
            raise ProtocolError("RPC cleanup query requires the original server/session/target identity")
    elif method == "cancel":
        if set(params) != {"requestId"} or type(params["requestId"]) is not int or not 1 <= params["requestId"] < 2**31:
            raise ProtocolError("RPC cancel requires one exact request id")
    elif method == "dbg":
        allowed = {"op", "timeout", "rva", "ea", "reg", "value", "expected", "size", "hex", "kind", "access", "record_trace", "record_image", "record_events", "count", "until", "expected_run_id", "expected_stop_seq", "after", "addressSpace", "interrupt_method", "thread_id", "anti_debug_profile", "exception_disposition"}
        if set(params) - allowed or params.get("op") not in {"load", "start", "bpt", "unbpt", "regs", "readmem", "writemem", "setreg", "step", "stepover", "cont", "suspend", "stop", "state", "event", "modules", "trace", "threads", "callstack"}:
            raise ProtocolError("RPC debug operation or parameter is unsupported")
        if "timeout" in params and (type(params["timeout"]) not in (int, float) or not 0 < params["timeout"] <= (120 if params["op"] == "cont" else 60)):
            raise ProtocolError("RPC timeout exceeds operation budget")
        for key in ("rva", "ea", "value", "expected", "until"):
            if key in params and key == "expected" and params["op"] == "writemem":
                if not isinstance(params[key], str) or re.fullmatch("(?:[0-9a-fA-F]{2}){1,4096}", params[key]) is None:
                    raise ProtocolError("RPC expected memory bytes are invalid")
                continue
            if key in params and (not isinstance(params[key], str) or re.fullmatch("0x[0-9a-fA-F]{1,16}", params[key]) is None):
                raise ProtocolError("RPC requires exact hexadecimal addresses/values")
        if "reg" in params and params["reg"] not in "rax rbx rcx rdx rsi rdi rsp rbp rip r8 r9 r10 r11 r12 r13 r14 r15 eax ebx ecx edx esi edi esp ebp eip eflags".split():
            raise ProtocolError("RPC register is unsupported")
        for key, maximum in (("count", 512 if params.get("record_trace") else 10000), ("size", 4096), ("expected_stop_seq", 2**31 - 1), ("after", 2**31 - 1)):
            if key in params and (type(params[key]) is not int or not 0 <= params[key] <= maximum or params[key] == 0 and key in ("count", "size")):
                raise ProtocolError("RPC integer exceeds operation budget")
        for key in ("record_trace", "record_image", "record_events"):
            if key in params and type(params[key]) is not bool:
                raise ProtocolError("RPC recording flags must be booleans")
        if "expected_run_id" in params and (not isinstance(params["expected_run_id"], str) or re.fullmatch("[0-9a-f]{32}", params["expected_run_id"]) is None):
            raise ProtocolError("RPC run id is invalid")
        if "kind" in params and params["kind"] not in ("software", "hardware") or "access" in params and params["access"] not in ("execute", "write", "readwrite"):
            raise ProtocolError("RPC breakpoint kind/access is unsupported")
        if "hex" in params and (not isinstance(params["hex"], str) or re.fullmatch("(?:[0-9a-fA-F]{2}){1,4096}", params["hex"]) is None):
            raise ProtocolError("RPC memory bytes are invalid or oversized")
        if params["op"] == "writemem" and ("hex" not in params or not {"ea", "rva"}.intersection(params)):
            raise ProtocolError("RPC memory write requires explicit address and bytes")
        if (params.get("record_image") or params.get("record_events")) and not params.get("record_trace") or params.get("record_trace") and params["op"] != "trace":
            raise ProtocolError("RPC recording flags require a trace operation")
        if "addressSpace" in params and params["addressSpace"] not in ("runtime", "rva"):
            raise ProtocolError("RPC address space is unsupported")
        if "interrupt_method" in params and (params["op"] != "suspend" or params["interrupt_method"] not in ("native-pause", "break-process")):
            raise ProtocolError("RPC interrupt requires typed suspend")
        if "thread_id" in params and (params["op"] != "regs" or type(params["thread_id"]) is not int or not 1 <= params["thread_id"] < 2**32):
            raise ProtocolError("RPC thread selection requires a positive DWORD and regs")
        if "anti_debug_profile" in params and (params["anti_debug_profile"] not in ("none", "scyllahide-thread-context") or params["anti_debug_profile"] != "none" and params["op"] != "start"):
            raise ProtocolError("RPC anti-debug profile requires typed start")
        if "exception_disposition" in params and (params["exception_disposition"] not in ("preserve", "handled") or params["exception_disposition"] != "preserve" and params["op"] != "cont"):
            raise ProtocolError("RPC exception disposition requires typed continuation")
    else:
        raise ProtocolError("RPC method is unsupported")
    return value
