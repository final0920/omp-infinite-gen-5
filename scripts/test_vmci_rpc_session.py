"""Regression of the actual lost-channel cancellation failure, without a target."""
from pathlib import Path
import queue
import sys
import threading
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "adapters/vmci"))
from vmci_rpc_session import serve_session

class BackendError(RuntimeError):
    pass

class Adapter:
    def __init__(self, confirm=True):
        self.requests = queue.Queue()
        self.wake = object()
        self.request_lock = threading.Lock()
        self.shutting_down = False
        self.cancel = threading.Event()
        self.started = threading.Event()
        self.exit_receipts = []
        self.confirm = confirm
        self.cleanup_called = False
    def enqueue(self, request):
        self.requests.put(request)
    def next_request(self):
        row = self.requests.get(timeout=2)
        return None if row is self.wake else row
    def claim_request(self, request):
        return not self.shutting_down
    def finish_request(self, ident):
        pass
    def error_result(self, error):
        self.cleanup()
        return {"code": "ECANCELLED", "message": str(error), "cleanedUp": self.confirm}
    def cleanup(self):
        if not self.cleanup_called:
            self.exit_receipts.append({"rootExitConfirmed": self.confirm, "jobClosed": True})
            self.cleanup_called = True

class Channel:
    def __init__(self, adapter, mode):
        self.adapter, self.mode = adapter, mode
        self.failed = False
        self.stream = self
        self.closed = threading.Event()
        self.received = 0
    def receive(self, deadline):
        self.received += 1
        if self.received == 1:
            return {"id": 1, "method": "dbg" if self.mode == "active" else "doctor", "params": {"op": "cont", "timeout": 30} if self.mode == "active" else {}}
        if self.mode == "active":
            assert self.adapter.started.wait(2)
            self.failed = True
            raise ConnectionError("peer disconnected during native wait")
        assert self.closed.wait(2)
        raise ConnectionError("closed test stream")
    def send(self, message, deadline):
        self.failed = True
        raise ConnectionError("response transport was lost")
    def close(self):
        self.closed.set()

class SessionTests(unittest.TestCase):
    def run_session(self, adapter, mode):
        session = {}
        channel = Channel(adapter, mode)
        def dispatch(request):
            adapter.started.set()
            if mode == "active":
                assert adapter.cancel.wait(2)
                raise BackendError("cancelled real active wait")
            return {"ok": True}, False
        serve_session(adapter, channel, session, dispatch, BackendError, lambda v: v, time.monotonic()+4)
        return session

    def test_disconnect_active_wait_keeps_receipt_and_allows_next_session(self):
        # The old implementation threw again when delivering the cancellation
        # response to the dead stream, terminating the entire service listener.
        first = self.run_session(Adapter(), "active")
        self.assertTrue(first["closed"] and first["readerExitConfirmed"])
        self.assertTrue(first["allOwnedRootsExitedAndJobsClosed"])
        self.assertEqual(first["undeliveredResults"], [{"id": 1, "errorCode": "ECANCELLED", "kind": "response"}])
        self.assertEqual(first["transportError"], "ConnectionError")
        second = self.run_session(Adapter(), "active")
        self.assertTrue(second["allOwnedRootsExitedAndJobsClosed"])

    def test_response_send_failure_also_confirms_cleanup(self):
        session = self.run_session(Adapter(), "send")
        self.assertTrue(session["readerExitConfirmed"] and session["allOwnedRootsExitedAndJobsClosed"])
        self.assertEqual(session["transportError"], "ConnectionError")
        self.assertEqual(len(session["undeliveredResults"]), 1)

    def test_unconfirmed_native_exit_forbids_another_session(self):
        with self.assertRaisesRegex(RuntimeError, "cleanup is unconfirmed"):
            self.run_session(Adapter(confirm=False), "active")

if __name__ == "__main__":
    unittest.main(verbosity=2)
