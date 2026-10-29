"""IG5 research wrapper for the public Windows VMCI/vSockets ABI.

Interface reference is pinned in upstream-source.json. No vendor implementation
is bundled. This module creates no IP sockets, changes no OS settings and runs
no subprocesses or debug targets.
"""
import ctypes as c
from ctypes import wintypes as w
import time
import socket  # Initialize Winsock through Python's normal process-local runtime.

ANY = 0xffffffff
HOST = 2
INVALID = c.c_size_t(-1).value

class Address(c.Structure):
    _fields_ = [("family", c.c_ushort), ("reserved", c.c_ushort), ("port", c.c_uint32), ("cid", c.c_uint32), ("zero", c.c_ubyte * 4)]

class PollFD(c.Structure):
    _fields_ = [("fd", c.c_size_t), ("events", c.c_short), ("revents", c.c_short)]

assert c.sizeof(Address) == 16
k = c.WinDLL("kernel32", use_last_error=True)
k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
k.CreateFileW.restype = w.HANDLE
k.DeviceIoControl.argtypes = [w.HANDLE, w.DWORD, c.c_void_p, w.DWORD, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
k.DeviceIoControl.restype = w.BOOL
k.CloseHandle.argtypes = [w.HANDLE]
ws = c.WinDLL("Ws2_32")
for name in ("socket", "accept"):
    getattr(ws, name).restype = c.c_size_t
ws.socket.argtypes = [c.c_int, c.c_int, c.c_int]
ws.bind.argtypes = [c.c_size_t, c.c_void_p, c.c_int]
ws.connect.argtypes = [c.c_size_t, c.c_void_p, c.c_int]
ws.listen.argtypes = [c.c_size_t, c.c_int]
ws.accept.argtypes = [c.c_size_t, c.c_void_p, c.POINTER(c.c_int)]
ws.closesocket.argtypes = [c.c_size_t]
ws.recv.argtypes = [c.c_size_t, c.c_void_p, c.c_int, c.c_int]
ws.send.argtypes = [c.c_size_t, c.c_void_p, c.c_int, c.c_int]
ws.setsockopt.argtypes = [c.c_size_t, c.c_int, c.c_int, c.c_void_p, c.c_int]
ws.getsockopt.argtypes = [c.c_size_t, c.c_int, c.c_int, c.c_void_p, c.POINTER(c.c_int)]
ws.ioctlsocket.argtypes = [c.c_size_t, c.c_long, c.POINTER(w.DWORD)]
ws.WSAPoll.argtypes = [c.POINTER(PollFD), c.c_ulong, c.c_int]
ws.WSAGetLastError.restype = c.c_int

def query(code):
    handle = k.CreateFileW(r"\\.\VMCI", 0x80000000, 0, None, 3, 0x40000000, None)
    if handle == c.c_void_p(-1).value:
        raise OSError(c.get_last_error(), "VMCI public device unavailable")
    try:
        value, returned = w.DWORD(ANY), w.DWORD()
        if not k.DeviceIoControl(handle, code, c.byref(value), 4, c.byref(value), 4, c.byref(returned), None) or returned.value != 4 or value.value == ANY:
            raise OSError(c.get_last_error(), "VMCI public capability query failed")
        return value.value
    finally:
        k.CloseHandle(handle)

def capabilities():
    return {"family": query(0x81032068), "localCID": query(0x8103206c), "version": query(0x81032058)}

class Stream:
    def __init__(self, family=None, handle=None):
        self.family = query(0x81032068) if family is None else family
        self.handle = ws.socket(self.family, 1, 0) if handle is None else handle
        if self.handle == INVALID:
            raise OSError(ws.WSAGetLastError(), "VMCI stream creation failed")
        timeout = c.c_int(1000)
        try:
            for option in (0x1005, 0x1006):
                if ws.setsockopt(self.handle, 0xffff, option, c.byref(timeout), 4):
                    raise OSError(ws.WSAGetLastError(), "VMCI I/O timeout setup failed")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle != INVALID:
            ws.closesocket(self.handle)
            self.handle = INVALID

    def wait(self, events, deadline):
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("VMCI deadline exceeded")
            poll = PollFD(self.handle, events, 0)
            result = ws.WSAPoll(c.byref(poll), 1, min(200, max(1, int(remaining * 1000))))
            if result < 0:
                raise OSError(ws.WSAGetLastError(), "VMCI poll failed")
            if result > 0:
                if poll.revents & events:
                    return
                raise ConnectionError("VMCI peer closed or poll failed")

    def bind(self, cid, port):
        address = Address(self.family, 0, port, cid)
        if ws.bind(self.handle, c.byref(address), 16):
            raise OSError(ws.WSAGetLastError(), "VMCI bind failed")

    def listen(self):
        if ws.listen(self.handle, 1):
            raise OSError(ws.WSAGetLastError(), "VMCI listen failed")

    def connect(self, cid, port, deadline):
        address = Address(self.family, 0, port, cid)
        mode = w.DWORD(1)
        if ws.ioctlsocket(self.handle, 0x8004667e, c.byref(mode)):
            raise OSError(ws.WSAGetLastError(), "VMCI nonblocking setup failed")
        if ws.connect(self.handle, c.byref(address), 16):
            error = ws.WSAGetLastError()
            if error != 10035:
                raise OSError(error, "VMCI connect failed")
            self.wait(0x10, deadline)
            error, length = c.c_int(), c.c_int(4)
            if ws.getsockopt(self.handle, 0xffff, 0x1007, c.byref(error), c.byref(length)) or error.value:
                raise OSError(error.value or ws.WSAGetLastError(), "VMCI connection completion failed")
        mode.value = 0
        if ws.ioctlsocket(self.handle, 0x8004667e, c.byref(mode)):
            raise OSError(ws.WSAGetLastError(), "VMCI blocking restore failed")

    def accept(self, deadline):
        self.wait(0x100, deadline)
        address, size = Address(), c.c_int(16)
        child = ws.accept(self.handle, c.byref(address), c.byref(size))
        if child == INVALID:
            raise OSError(ws.WSAGetLastError(), "VMCI accept failed")
        if size.value != 16 or address.family != self.family:
            ws.closesocket(child)
            raise ConnectionError("VMCI peer address ABI mismatch")
        return Stream(self.family, child), {"cid": address.cid, "port": address.port}

    def receive(self, maximum, deadline):
        assert 1 <= maximum <= 65536
        self.wait(0x100, deadline)
        buffer = c.create_string_buffer(maximum)
        count = ws.recv(self.handle, buffer, maximum, 0)
        if count <= 0:
            raise ConnectionError("VMCI receive failed or peer disconnected")
        return buffer.raw[:count]

    def send(self, data, deadline):
        if not isinstance(data, bytes) or not 1 <= len(data) <= 65536:
            raise ValueError("VMCI send budget")
        offset = 0
        while offset < len(data):
            self.wait(0x10, deadline)
            tail = data[offset:]
            buffer = c.create_string_buffer(tail)
            count = ws.send(self.handle, buffer, len(tail), 0)
            if count <= 0:
                raise ConnectionError("VMCI send failed")
            offset += count

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
