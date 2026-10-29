"""Correlated typed VMCI requests; disconnect never means cleanup confirmed."""
from concurrent.futures import Future
import threading
import time
from vmci_rpc import client_handshake, validate_request
from win_vmci import Stream, HOST

class RemoteError(RuntimeError):
    def __init__(self, error):
        self.detail = error
        super().__init__(str(error.get("code")) + ": " + str(error.get("message")))

class Client:
    def __init__(self, cid, port, key, bundle_hash, transcript):
        self.condition = threading.Condition()
        self.pending, self.events = {}, []
        self.transcript = transcript
        self.lock = threading.Lock()
        self.serial = 0
        self.closed = False
        try:
            connect_deadline = time.monotonic() + 10
            for attempt in range(80):
                self.stream = Stream()
                try:
                    self.stream.connect(cid, port, connect_deadline)
                    break
                except (OSError, ConnectionError):
                    self.stream.close()
                    if attempt == 79 or time.monotonic() >= connect_deadline:
                        raise
                    time.sleep(.125)
            # This margin is only for the previous session's confirmed cleanup;
            # never retry an authenticated request or a running debugger command.
            self.channel, self.hello = client_handshake(self.stream, key, cid, HOST, bundle_hash, time.monotonic() + 15)
        except BaseException:
            self.stream.close()
            raise
        self.thread = threading.Thread(target=self.reader, daemon=True)
        self.thread.start()

    def reader(self):
        error = ConnectionError("VMCI client closed")
        try:
            while not self.closed:
                message = self.channel.receive(time.monotonic() + 600)
                if isinstance(message, dict) and set(message) == {"event"}:
                    with self.condition:
                        self.events.append(message["event"])
                        self.condition.notify_all()
                    continue
                if not isinstance(message, dict) or type(message.get("id")) is not int or set(message) not in ({"id", "result"}, {"id", "error"}):
                    raise ValueError("Invalid correlated RPC response")
                with self.lock:
                    pending = self.pending.pop(message["id"], None)
                if pending is None:
                    raise ValueError("Unknown or duplicate RPC response id")
                future, row = pending
                row["response"] = message
                future.set_exception(RemoteError(message["error"])) if "error" in message else future.set_result(message["result"])
        except BaseException as caught:
            error = caught
        finally:
            with self.lock:
                pending, self.pending = self.pending, {}
            for future, row in pending.values():
                row["transportError"] = type(error).__name__
                if not future.done():
                    future.set_exception(error)
            with self.condition:
                self.condition.notify_all()

    def begin(self, method, params=None):
        with self.lock:
            self.serial += 1
            request = validate_request({"id": self.serial, "method": method, "params": params or {}})
            future = Future()
            row = {"request": request, "response": None}
            self.pending[self.serial] = (future, row)
            if self.transcript is not None:
                self.transcript.append(row)
        try:
            self.channel.send(request, time.monotonic() + 10)
        except BaseException:
            self.close()
            raise
        return request["id"], future

    def request(self, method, params=None, timeout=65):
        _, future = self.begin(method, params)
        return future.result(timeout=timeout)

    def wait_new_running_event(self, count, run_id, timeout=5):
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                matches = [event for event in self.events[count:] if event.get("runId") == run_id and event.get("type") == "EVENT_RESUME_DEBUG"]
                if matches:
                    return matches[-1]
                if not self.thread.is_alive() or time.monotonic() >= deadline:
                    raise TimeoutError("No authenticated native resume callback observed")
                self.condition.wait(min(.2, deadline-time.monotonic()))

    def close(self):
        self.closed = True
        self.stream.close()
        if self.thread is not threading.current_thread():
            self.thread.join(timeout=2)
        if self.thread.is_alive() and self.thread is not threading.current_thread():
            raise RuntimeError("VMCI host reader exit not confirmed")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
