"""Real fragmented authenticated channel around the production session loop."""
from pathlib import Path
import sys
import threading
import time
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'adapters/vmci'))
from test_vmci_rpc import pair
from test_vmci_rpc_session import Adapter, BackendError
from vmci_rpc import Channel, mac, verify_tag, ProtocolError
from vmci_rpc_session import serve_session

class CloseTests(unittest.TestCase):
    def serve(self):
        a, b = pair(); client = Channel(a, '1'*64, b'k'*32, False); server = Channel(b, '1'*64, b'k'*32, True)
        adapter, session, errors = Adapter(), {}, []
        def dispatch(request):
            adapter.cleanup()
            return {'ok': True, 'receipt': 'x'*4096}, True
        def run():
            try: serve_session(adapter, server, session, dispatch, BackendError, lambda value: value, time.monotonic()+5)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=run); thread.start()
        return client, thread, session, errors

    def test_terminal_frame_is_complete_and_stream_waits_for_authenticated_ack(self):
        client, thread, session, errors = self.serve()
        client.send({'id': 1, 'method': 'session_close', 'params': {}}, time.monotonic()+1)
        value = client.receive(time.monotonic()+1)
        self.assertEqual(value['result']['receipt'], 'x'*4096); self.assertTrue(thread.is_alive())
        client.send({'id': 2, 'method': 'close_ack', 'params': {}}, time.monotonic()+1)
        thread.join(3); self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        self.assertTrue(session['terminalAckConfirmed']); self.assertTrue(session['readerExitConfirmed'])

    def test_disconnected_peer_does_not_become_an_ack(self):
        client, thread, session, errors = self.serve()
        client.send({'id': 1, 'method': 'session_close', 'params': {}}, time.monotonic()+1)
        client.receive(time.monotonic()+1); client.stream.close(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        self.assertFalse(session['terminalAckConfirmed']); self.assertTrue(session['allOwnedRootsExitedAndJobsClosed'])

    def test_terminal_receipt_hmac_binds_old_session_and_process_cleanup(self):
        value = {'serverInstanceId': '1'*32, 'sessionId': '2'*64, 'nativeRoots': [{'rootId': '3'*32, 'pid': 1234, 'rootExitConfirmed': True, 'jobClosed': True}]}
        tag = mac(b'k'*32, 'terminal-cleanup', value); verify_tag(b'k'*32, 'terminal-cleanup', value, tag)
        for changed in ({**value, 'sessionId': '4'*64}, {**value, 'nativeRoots': []}):
            with self.assertRaises(ProtocolError): verify_tag(b'k'*32, 'terminal-cleanup', changed, tag)

if __name__ == '__main__': unittest.main(verbosity=2)
