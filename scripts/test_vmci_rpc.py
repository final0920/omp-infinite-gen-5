"""Adversarial protocol tests; no VM, target, IP socket or native debugger."""
import collections
import copy
import hashlib
from pathlib import Path
import struct
import sys
import threading
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters/vmci"))
import vmci_rpc as rpc

class Pipe:
    def __init__(self):
        self.buffer = bytearray()
        self.condition = threading.Condition()
        self.closed = False
    def send(self, data, deadline):
        with self.peer.condition:
            if self.closed or self.peer.closed:
                raise ConnectionError("closed test pipe")
            self.peer.buffer.extend(data)
            self.peer.condition.notify_all()
    def receive(self, maximum, deadline):
        with self.condition:
            while not self.buffer and not self.closed and not self.peer.closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("test pipe deadline")
                self.condition.wait(remaining)
            if not self.buffer:
                raise ConnectionError("closed test pipe")
            # Deliberately fragment all packets, including 4-byte size headers.
            count = min(maximum, 7, len(self.buffer))
            data = bytes(self.buffer[:count])
            del self.buffer[:count]
            return data
    def close(self):
        self.closed = True
        for p in (self, self.peer):
            with p.condition:
                p.condition.notify_all()

def pair():
    a, b = Pipe(), Pipe()
    a.peer, b.peer = b, a
    return a, b

class ProtocolTests(unittest.TestCase):
    def channels(self):
        a, b = pair()
        return rpc.Channel(a, "1"*64, b"k"*32, False), rpc.Channel(b, "1"*64, b"k"*32, True)

    def handshake(self, wrong_key=False, wrong_bundle=False):
        a, b = pair()
        errors, server = [], []
        def run():
            try:
                server.append(rpc.server_handshake(b, b"k"*32, 100, 2, "a"*64, "e"*32, time.monotonic()+1)[0])
            except Exception as error:
                errors.append(error)
        thread = threading.Thread(target=run)
        thread.start()
        try:
            client = rpc.client_handshake(a, b"z"*32 if wrong_key else b"k"*32, 100, 2, "b"*64 if wrong_bundle else "a"*64, time.monotonic()+1)[0]
        except Exception:
            a.close(); thread.join(2)
            self.assertFalse(thread.is_alive())
            raise
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return client, server[0]

    def test_fragmented_bidirectional_authenticated_handshake(self):
        client, server = self.handshake()
        request = {"id": 1, "method": "doctor", "params": {}}
        client.send(request, time.monotonic()+1)
        self.assertEqual(server.receive(time.monotonic()+1), request)
        server.send({"id": 1, "result": {"ok": True}}, time.monotonic()+1)
        self.assertEqual(client.receive(time.monotonic()+1), {"id": 1, "result": {"ok": True}})
        self.assertEqual(client.session_id, server.session_id)

    def test_wrong_pairing_key_rejected(self):
        with self.assertRaisesRegex(rpc.ProtocolError, "authentication"):
            self.handshake(wrong_key=True)

    def test_wrong_bundle_rejected(self):
        with self.assertRaisesRegex(rpc.ProtocolError, "identity"):
            self.handshake(wrong_bundle=True)

    def test_fresh_handshakes_have_different_session_keys(self):
        first, _ = self.handshake()
        second, _ = self.handshake()
        self.assertNotEqual(first.session_id, second.session_id)
        self.assertNotEqual(first.key, second.key)

    def test_tampered_message_rejected_and_channel_closed(self):
        client, server = self.channels()
        client.send({"id": 1, "method": "doctor", "params": {}}, time.monotonic()+1)
        raw = bytes(server.stream.buffer).replace(b'"id":1', b'"id":2')
        server.stream.buffer[:] = raw
        with self.assertRaisesRegex(rpc.ProtocolError, "authentication"):
            server.receive(time.monotonic()+1)
        self.assertTrue(server.failed)
        self.assertTrue(server.stream.closed)

    def test_replay_rejected(self):
        client, server = self.channels()
        client.send({"id": 1}, time.monotonic()+1)
        replay = bytes(server.stream.buffer)
        server.receive(time.monotonic()+1)
        server.stream.buffer.extend(replay)
        with self.assertRaisesRegex(rpc.ProtocolError, "sequence"):
            server.receive(time.monotonic()+1)

    def test_reflected_direction_rejected(self):
        client, server = self.channels()
        client.send({"id": 1}, time.monotonic()+1)
        client.stream.buffer.extend(server.stream.buffer)
        server.stream.buffer.clear()
        with self.assertRaisesRegex(rpc.ProtocolError, "authentication"):
            client.receive(time.monotonic()+1)

    def test_old_session_rejected(self):
        client, server = self.channels()
        client.session_id = "2"*64
        client.send({"id": 1}, time.monotonic()+1)
        with self.assertRaisesRegex(rpc.ProtocolError, "session"):
            server.receive(time.monotonic()+1)

    def test_oversized_header_rejected_without_payload_read(self):
        client, server = self.channels()
        client.stream.send(struct.pack("<I", rpc.MAX_REQUEST+1), time.monotonic()+1)
        with self.assertRaisesRegex(rpc.ProtocolError, "size"):
            server.receive(time.monotonic()+1)

    def test_noncanonical_duplicate_nonfinite_and_deep_json_rejected(self):
        for data in [b'{"x":1,"x":2}', b'{ "x":1}', b'{"x":NaN}', b'{"x":1e999}', b'['*2000+b'0'+b']'*2000]:
            with self.subTest(data=data[:30]), self.assertRaises(rpc.ProtocolError):
                rpc.decode(data)

    def test_request_catalog_and_command_path_injection_refused(self):
        for method, params in [("open", {"path": "C:/elsewhere.exe"}), ("open", {"fixtureId": "../other"}), ("shell", {}), ("dbg", {"op": "start", "path": "C:/elsewhere.exe"}), ("dbg", {"op": "step", "cmd": "run"}), ("dbg", {"op": "writemem", "hex": "cc"}), ("dbg", {"op": "readmem", "ea": "0x1;run"})]:
            with self.subTest(method=method,params=params), self.assertRaises(rpc.ProtocolError):
                rpc.validate_request({"id": 1, "method": method, "params": params})

    def test_boolean_ids_cancel_id_and_trace_budgets_refused(self):
        for params in ({'op': 'trace', 'record_trace': True, 'record_events': 1}, {'op': 'trace', 'record_events': True}, {'op': 'step', 'record_trace': True, 'record_events': True}):
            with self.subTest(params=params), self.assertRaises(rpc.ProtocolError):
                rpc.validate_request({'id': 1, 'method': 'dbg', 'params': params})
        for request in [{"id": True, "method": "doctor", "params": {}}, {"id": 1, "method": "cancel", "params": {}}, {"id": 1, "method": "cancel", "params": {"requestId": False}}, {"id": 1, "method": "dbg", "params": {"op": "trace", "record_trace": True, "count": 513}}, {"id": 1, "method": "dbg", "params": {"op": "step", "timeout": 61}}, {"id": 1, "method": "dbg", "params": {"op": "cont", "timeout": 121}}]:
            with self.subTest(request=request), self.assertRaises(rpc.ProtocolError):
                rpc.validate_request(request)

    def test_typed_boundary_requests_accepted(self):
        rpc.validate_request({'id': 1, 'method': 'dbg', 'params': {'op': 'trace', 'record_trace': True, 'record_events': True, 'count': 512}})
        for method, params in [("doctor", {}), ("open", {"targetId": "owned-add64"}), ("dbg", {"op": "cont", "timeout": 120}), ("dbg", {"op": "trace", "record_trace": True, "record_image": True, "count": 512}), ("cancel", {"requestId": 2**31-1}), ("dbg", {"op": "setreg", "reg": "rcx", "value": "0xffffffffffffffff", "expected": "0x0"}), ("service_close", {})]:
            request = {"id": 1, "method": method, "params": params}
            self.assertEqual(rpc.validate_request(request), request)

    def test_message_budget_refused(self):
        client, server = self.channels()
        client.send_sequence = rpc.MAX_MESSAGES
        with self.assertRaisesRegex(rpc.ProtocolError, "budget"):
            client.send({"id": 1}, time.monotonic()+1)

if __name__ == "__main__":
    unittest.main(verbosity=2)
