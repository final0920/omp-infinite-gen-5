"""One bounded debugger session; transport loss cannot strand owned processes."""
import contextlib
import queue
import threading
import time
from vmci_rpc import ProtocolError, validate_request

TRANSPORT_ERRORS = (ConnectionError, OSError, TimeoutError, ProtocolError)

def serve_session(adapter, channel, session, dispatch, rpc_error, plain, deadline):
    seen_ids = set()
    terminal_pending, terminal_ack = threading.Event(), threading.Event()
    session.update(requests=[], transportError=None, cleanup=[], closed=False, undeliveredResults=[])

    def send(message):
        if channel.failed:
            session["undeliveredResults"].append({"id": message.get("id"), "errorCode": message.get("error", {}).get("code"), "kind": "event" if "event" in message else "response"})
            return False
        try:
            channel.send(plain(message), min(deadline, time.monotonic() + 30))
            return True
        except TRANSPORT_ERRORS as error:
            session["transportError"] = session["transportError"] or type(error).__name__
            session["undeliveredResults"].append({"id": message.get("id"), "errorCode": message.get("error", {}).get("code"), "kind": "event" if "event" in message else "response"})
            adapter.cancel.set()
            return False

    adapter.respond = adapter.emit_running = send

    def reader():
        try:
            while not adapter.shutting_down:
                request = validate_request(channel.receive(deadline))
                if request["id"] in seen_ids:
                    raise ProtocolError("RPC request id reused in this session")
                seen_ids.add(request["id"])
                session["requests"].append({"id": request["id"], "method": request["method"], "op": request["params"].get("op")})
                if request["method"] == "close_ack":
                    if not terminal_pending.is_set(): raise ProtocolError("Close acknowledgement precedes terminal response")
                    terminal_ack.set()
                    break
                if request["method"] == "cancel":
                    if not send({"id": request["id"], "result": adapter.cancel_request(request["params"])}):
                        break
                else:
                    adapter.enqueue(request)
        except BaseException as error:
            session["transportError"] = session["transportError"] or type(error).__name__
        finally:
            with adapter.request_lock:
                adapter.shutting_down = True
                adapter.cancel.set()
            with contextlib.suppress(queue.Full):
                adapter.requests.put_nowait(adapter.wake)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    try:
        while not adapter.shutting_down:
            request = adapter.next_request()
            if request is None:
                break
            if not adapter.claim_request(request):
                if not send({"id": request["id"], "error": {"code": "ECANCELLED", "message": "Queued remote request cancelled", "cancelledBeforeExecution": True, "cleanedUp": False}}):
                    break
                continue
            try:
                result, stop = dispatch(request)
                if stop: terminal_pending.set()
                delivered = send({"id": request["id"], "result": result})
                if stop and delivered:
                    # Keep the stream alive until the peer received the signed
                    # terminal receipt. A timeout/disconnect is not an ACK.
                    session["terminalAckConfirmed"] = terminal_ack.wait(timeout=2)
                if stop or not delivered:
                    break
            except rpc_error as error:
                detail = adapter.error_result(error)
                if not send({"id": request["id"], "error": detail}):
                    break
            except TRANSPORT_ERRORS as error:
                session["transportError"] = session["transportError"] or type(error).__name__
                break
            finally:
                adapter.finish_request(request["id"])
    finally:
        adapter.cancel.set()
        adapter.cleanup()
        adapter.shutting_down = True
        channel.stream.close()
        thread.join(timeout=2)
        session["readerExitConfirmed"] = not thread.is_alive()
        session["cleanup"] = list(adapter.exit_receipts)
        session["closed"] = True
        session["allOwnedRootsExitedAndJobsClosed"] = all(row["rootExitConfirmed"] and row["jobClosed"] for row in adapter.exit_receipts)
        if thread.is_alive() or not session["allOwnedRootsExitedAndJobsClosed"]:
            raise RuntimeError("Guest session cleanup is unconfirmed; refuse another session")
