"""Read-only AMD64 thread context of an already stopped owned debuggee.

CONTEXТ layout matches Windows SDK winnt.h: 16-byte alignment, 1232 bytes,
ContextFlags at 48 and integer/control registers at 120..255. No thread suspend,
context write, process attach, or selected-debugger-thread change occurs.
"""
import ctypes
from ctypes import wintypes as w
import struct


def decode_context(data):
    """Decode the Windows AMD64 CONTEXT layout without losing address bits."""
    if len(data) != 1232: raise ValueError('Incomplete AMD64 thread context')
    names = 'rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15 rip'.split()
    regs = dict(zip(names, struct.unpack_from('<17Q', data, 120)))
    regs['eflags'] = struct.unpack_from('<I', data, 68)[0]
    regs.update(zip(('dr0', 'dr1', 'dr2', 'dr3', 'dr6', 'dr7'), struct.unpack_from('<6Q', data, 72)))
    return {name: hex(value) for name, value in regs.items()}


def debugger_visibility(thread, ntdll):
    """Observe ThreadHideFromDebugger; never change it or guess on failure."""
    query = ntdll.NtQueryInformationThread
    query.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.ULONG, ctypes.POINTER(w.ULONG)]
    query.restype = ctypes.c_long
    hidden = ctypes.c_ubyte(); returned = w.ULONG()
    status = query(thread, 0x11, ctypes.byref(hidden), 1, ctypes.byref(returned))
    status = int(status) & 0xffffffff
    valid = status == 0 and hidden.value in (0, 1)
    return {'hiddenFromDebugger': bool(hidden.value) if valid else None,
            'querySucceeded': valid, 'ntStatus': hex(status),
            'source': 'Windows-NtQueryInformationThread-ThreadHideFromDebugger',
            'threadModified': False}


def read_thread(adapter, thread_id, RpcError, include_debug_status=False):
    if adapter.target['bits'] != 64 or not adapter.job or not adapter.job.handle:
        raise RpcError('ENOTSUPPORTED', 'Selected thread context requires the owned native x64 debugger')
    before = adapter.state()
    if before['state'] != 'suspended': raise RpcError('ESTATE', 'Selected thread register read requires a paused debuggee')
    available = adapter.call('get_threads')['threads']
    if not any(row['threadId'] == thread_id for row in available): raise ValueError('Thread does not belong to the current debuggee')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]; kernel.OpenThread.restype = w.HANDLE
    kernel.GetProcessIdOfThread.argtypes = [w.HANDLE]; kernel.GetProcessIdOfThread.restype = w.DWORD
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]; kernel.OpenProcess.restype = w.HANDLE
    kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)]
    kernel.GetThreadContext.argtypes = [w.HANDLE, ctypes.c_void_p]; kernel.GetThreadContext.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    access = 0x0808 | (0x0040 if include_debug_status else 0)  # QUERY_INFORMATION for the NT visibility query
    thread = kernel.OpenThread(access, False, thread_id)
    visibility_open_error = None
    if not thread and include_debug_status:
        visibility_open_error = ctypes.get_last_error()
        thread = kernel.OpenThread(0x0808, False, thread_id)
    if not thread: raise RpcError('EBACKEND', 'Selected thread could not be opened', winError=ctypes.get_last_error())
    process = None
    try:
        if kernel.GetProcessIdOfThread(thread) != before['pid']: raise RpcError('ESTATE', 'Selected thread process changed')
        process = kernel.OpenProcess(0x1000, False, before['pid'])
        in_job = w.BOOL()
        if not process or not kernel.IsProcessInJob(process, adapter.job.handle, ctypes.byref(in_job)) or not in_job.value:
            raise RpcError('ESTATE', 'Selected thread is outside the owned debugger job')
        buffer = ctypes.create_string_buffer(1232 + 15)
        address = (ctypes.addressof(buffer) + 15) & ~15
        ctypes.c_uint32.from_address(address + 48).value = 0x10001f
        if not kernel.GetThreadContext(thread, address): raise RpcError('EBACKEND', 'Selected thread context read failed', winError=ctypes.get_last_error())
        data = ctypes.string_at(address, 1232)
        visibility = None
        if include_debug_status:
            visibility = debugger_visibility(thread, ctypes.WinDLL('ntdll')) if visibility_open_error is None else {
                'hiddenFromDebugger': None, 'querySucceeded': False, 'ntStatus': None,
                'winError': visibility_open_error, 'source': 'Windows-NtQueryInformationThread-ThreadHideFromDebugger',
                'threadModified': False}
        after = adapter.state()
        if after['state'] != 'suspended' or any(after.get(key) != before.get(key) for key in ['pid', 'tid', 'runId', 'stopSeq', 'nativeRunEpoch']):
            raise RpcError('ESTATE', 'Pause changed during selected thread context read')
        registers = decode_context(data)
        return {'registers': registers, 'debuggerVisibility': visibility} if include_debug_status else registers
    finally:
        if process: kernel.CloseHandle(process)
        kernel.CloseHandle(thread)
