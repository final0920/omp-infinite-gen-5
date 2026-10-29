"""Own one trusted analysis subprocess in a Windows job, never a target binary.

The job and handle lists are assigned atomically by CreateProcessW, before the
suspended primary thread resumes. No PID attach, shell, breakaway or security
setting changes. Closing the worker's job handle also kills its analysis child.
"""
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import subprocess
import time


class OwnedProcessError(RuntimeError):
    def __init__(self, message, *, child_exit_confirmed):
        super().__init__(message)
        self.child_exit_confirmed = child_exit_confirmed


class _BasicLimit(C.Structure):
    _fields_ = [('process_time', C.c_int64), ('job_time', C.c_int64),
                ('flags', W.DWORD), ('min_working', C.c_size_t),
                ('max_working', C.c_size_t), ('active_processes', W.DWORD),
                ('affinity', C.c_size_t), ('priority', W.DWORD), ('scheduling', W.DWORD)]


class _Io(C.Structure):
    _fields_ = [(name, C.c_uint64) for name in
                ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]


class _Limits(C.Structure):
    _fields_ = [('basic', _BasicLimit), ('io', _Io),
                ('process_memory', C.c_size_t), ('job_memory', C.c_size_t),
                ('peak_process_memory', C.c_size_t), ('peak_job_memory', C.c_size_t)]


class _Startup(C.Structure):
    _fields_ = [('cb', W.DWORD), ('reserved', W.LPWSTR), ('desktop', W.LPWSTR),
                ('title', W.LPWSTR), ('x', W.DWORD), ('y', W.DWORD),
                ('x_size', W.DWORD), ('y_size', W.DWORD),
                ('x_chars', W.DWORD), ('y_chars', W.DWORD),
                ('fill', W.DWORD), ('flags', W.DWORD),
                ('show', W.WORD), ('reserved_size', W.WORD),
                ('reserved_bytes', C.c_void_p), ('stdin', W.HANDLE),
                ('stdout', W.HANDLE), ('stderr', W.HANDLE)]


class _StartupEx(C.Structure):
    _fields_ = [('startup', _Startup), ('attributes', C.c_void_p)]


class _Process(C.Structure):
    _fields_ = [('process', W.HANDLE), ('thread', W.HANDLE),
                ('pid', W.DWORD), ('tid', W.DWORD)]


def _api():
    if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
        raise OwnedProcessError('Experimental lifter requires Windows x64', child_exit_confirmed=True)
    k = C.WinDLL('kernel32', use_last_error=True)
    declarations = {
        'CreateJobObjectW': ([C.c_void_p, W.LPCWSTR], W.HANDLE),
        'SetInformationJobObject': ([W.HANDLE, C.c_int, C.c_void_p, W.DWORD], W.BOOL),
        'QueryInformationJobObject': ([W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p], W.BOOL),
        'InitializeProcThreadAttributeList': ([C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t)], W.BOOL),
        'UpdateProcThreadAttribute': ([C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p], W.BOOL),
        'DeleteProcThreadAttributeList': ([C.c_void_p], None),
        'CreateProcessW': ([W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD,
                            C.c_void_p, W.LPCWSTR, C.c_void_p, C.POINTER(_Process)], W.BOOL),
        'IsProcessInJob': ([W.HANDLE, W.HANDLE, C.POINTER(W.BOOL)], W.BOOL),
        'ResumeThread': ([W.HANDLE], W.DWORD),
        'WaitForSingleObject': ([W.HANDLE, W.DWORD], W.DWORD),
        'GetExitCodeProcess': ([W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
        'TerminateJobObject': ([W.HANDLE, W.UINT], W.BOOL),
        'CloseHandle': ([W.HANDLE], W.BOOL),
    }
    for name, (arguments, result) in declarations.items():
        function = getattr(k, name); function.argtypes = arguments; function.restype = result
    return k


def run_owned(executable, arguments, directory, *, budget_ms=50000,
              memory_bytes=2 * 1024 ** 3, output_bytes=4 * 1024 ** 2,
              cancel=None, on_started=None, env=None):
    """Run the caller-verified analysis executable; resource/cleanup facts only.

    Outputs and the suspended-child capability belong exclusively to this call.
    Memory is an OS job cap; output sizes are observed every20ms and bounded on
    subsequent reads. Unexpected worker termination cannot orphan a live child.
    """
    if (isinstance(budget_ms, bool) or not isinstance(budget_ms, int) or not 1 <= budget_ms <= 50000 or
            isinstance(memory_bytes, bool) or not isinstance(memory_bytes, int) or not 16 * 1024 ** 2 <= memory_bytes <= 2 * 1024 ** 3 or
            isinstance(output_bytes, bool) or not isinstance(output_bytes, int) or not 1024 <= output_bytes <= 4 * 1024 ** 2):
        raise OwnedProcessError('Invalid owned-process resource limits', child_exit_confirmed=True)
    executable = os.fspath(executable)
    if (not os.path.isabs(executable) or '\0' in executable or
            not isinstance(arguments, (list, tuple)) or
            any(not isinstance(a, str) or '\0' in a for a in arguments)):
        raise OwnedProcessError('Analysis executable and argv must be explicit', child_exit_confirmed=True)
    command = subprocess.list2cmdline([executable, *arguments])
    if len(command) > 30000:
        raise OwnedProcessError('Analysis command exceeds its byte budget', child_exit_confirmed=True)
    directory = Path(directory)
    if not directory.is_absolute() or not directory.is_dir() or directory.is_symlink():
        raise OwnedProcessError('Invalid owned output directory', child_exit_confirmed=True)
    if cancel is not None and cancel.is_set():
        raise OwnedProcessError('Analysis cancelled before launch', child_exit_confirmed=True)
    k = _api()
    import msvcrt
    job, process, attribute_buffer, attributes_live = None, _Process(), None, False
    streams, inherited, created, exited = [], [], False, False
    started = time.monotonic(); reason = None; failure = None; peak = None
    try:
        job = k.CreateJobObjectW(None, None)
        if not job: raise C.WinError(C.get_last_error())
        limits = _Limits()
        limits.basic.flags = 0x2000 | 0x100 | 0x8  # kill-on-close, process memory, one process
        limits.basic.active_processes = 1; limits.process_memory = memory_bytes
        if not k.SetInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits)):
            raise C.WinError(C.get_last_error())
        for name, mode in ((os.devnull, 'rb'), (directory / 'stdout.log', 'xb'), (directory / 'stderr.log', 'xb')):
            streams.append(open(name, mode, buffering=0))
        handles = [msvcrt.get_osfhandle(f.fileno()) for f in streams]
        for handle in handles:
            inherited.append((handle, os.get_handle_inheritable(handle)))
            os.set_handle_inheritable(handle, True)
        size = C.c_size_t()
        k.InitializeProcThreadAttributeList(None, 2, 0, C.byref(size))
        if not size.value: raise C.WinError(C.get_last_error())
        attribute_buffer = C.create_string_buffer(size.value)
        if not k.InitializeProcThreadAttributeList(attribute_buffer, 2, 0, C.byref(size)):
            raise C.WinError(C.get_last_error())
        attributes_live = True
        handle_list = (W.HANDLE * len(handles))(*handles)
        job_list = (W.HANDLE * 1)(job)
        # Attribute job-list assignment is atomic with creation, eliminating
        # the suspended-but-not-yet-assigned orphan window.
        for key, value in ((0x20002, handle_list), (0x2000D, job_list)):
            if not k.UpdateProcThreadAttribute(attribute_buffer, 0, key, C.byref(value), C.sizeof(value), None, None):
                raise C.WinError(C.get_last_error())
        startup = _StartupEx(); startup.startup.cb = C.sizeof(startup)
        startup.startup.flags = 0x100 | 0x1; startup.startup.show = 0
        startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = handles
        startup.attributes = C.cast(attribute_buffer, C.c_void_p)
        minimal = {key: os.environ[key] for key in ('SYSTEMROOT', 'WINDIR', 'IG5_HOME') if key in os.environ}
        minimal.update({'TEMP': str(directory), 'TMP': str(directory),
                        'PATH': os.path.dirname(executable) + os.pathsep + os.path.join(os.environ.get('SYSTEMROOT', 'C:\\Windows'), 'System32')})
        if env:
            # Callers may set only fixed analysis controls; never inherit API keys.
            if any(key not in ('MERGEN_MAX_BLOCK_BUDGET', 'MERGEN_CRASH_REPORT') or not isinstance(value, str) for key, value in env.items()):
                raise ValueError('Unsupported analysis environment override')
            minimal.update(env)
        environment = C.create_unicode_buffer('\0'.join(k + '=' + v for k, v in sorted(minimal.items())) + '\0\0')
        flags = 0x08000000 | 0x4 | 0x400 | 0x80000  # hidden, suspended, Unicode, extended startup
        if not k.CreateProcessW(executable, C.create_unicode_buffer(command), None, None, True,
                                flags, environment, str(directory), C.byref(startup), C.byref(process)):
            raise C.WinError(C.get_last_error())
        created = True
        member = W.BOOL()
        if not k.IsProcessInJob(process.process, job, C.byref(member)) or not member.value:
            raise RuntimeError('Owned analysis child was not assigned to its job')
        if on_started: on_started(int(process.pid))
        if cancel is not None and cancel.is_set():
            raise RuntimeError('Analysis cancelled before primary-thread resume')
        resumed = k.ResumeThread(process.thread)
        if resumed == 0xFFFFFFFF: raise C.WinError(C.get_last_error())
        if resumed != 1: raise RuntimeError('Owned primary thread had an unexpected suspend count')
        k.CloseHandle(process.thread); process.thread = None
        watched = [directory / name for name in ('stdout.log', 'stderr.log', 'output.ll',
                   'output_no_opts.ll', 'output_diagnostics.json', 'mergen-crash.txt')]
        while True:
            wait = k.WaitForSingleObject(process.process, 20)
            if wait == 0: exited = True; break
            if wait != 258: raise C.WinError(C.get_last_error())
            if cancel is not None and cancel.is_set(): reason = 'cancelled'
            elif (time.monotonic() - started) * 1000 >= budget_ms: reason = 'deadline'
            elif any(p.exists() and p.stat().st_size > output_bytes for p in watched): reason = 'output-limit'
            if reason:
                if not k.TerminateJobObject(job, 1): raise C.WinError(C.get_last_error())
                exited = k.WaitForSingleObject(process.process, 5000) == 0
                break
        if reason is None and any(p.exists() and p.stat().st_size > output_bytes for p in watched):
            reason = 'output-limit'
    except Exception as exc:
        failure = exc
    finally:
        if created and not exited:
            k.TerminateJobObject(job, 1)
            exited = k.WaitForSingleObject(process.process, 5000) == 0
        if job:
            observed = _Limits()
            if k.QueryInformationJobObject(job, 9, C.byref(observed), C.sizeof(observed), None):
                peak = int(observed.peak_process_memory)
        code = W.DWORD(); exit_code = None
        if created and exited:
            exit_code = int(code.value) if k.GetExitCodeProcess(process.process, C.byref(code)) else None
        for handle, previous in inherited:
            try: os.set_handle_inheritable(handle, previous)
            except OSError: pass
        if attributes_live: k.DeleteProcThreadAttributeList(attribute_buffer)
        for handle in (process.thread, process.process, job):
            if handle: k.CloseHandle(handle)
        for stream in streams: stream.close()
    if failure:
        raise OwnedProcessError('Owned analysis process failed: ' + str(failure), child_exit_confirmed=not created or exited) from failure
    if not exited:
        raise OwnedProcessError('Owned analysis child exit was not confirmed', child_exit_confirmed=False)
    return {'status': 'cancelled' if reason == 'cancelled' else 'limited' if reason else 'completed',
            'limitReason': reason, 'exitCode': exit_code, 'pid': int(process.pid),
            'childExitConfirmed': True, 'jobAssignedAtCreation': True,
            'elapsedMs': int((time.monotonic() - started) * 1000),
            'peakPrivateBytes': peak, 'memoryLimitBytes': memory_bytes,
            'memoryEnforcement': 'Windows per-process job memory limit before primary-thread resume',
            'outputEnforcement': '20ms file-size observation; bounded reads required',
            'activeProcessLimit': 1}
