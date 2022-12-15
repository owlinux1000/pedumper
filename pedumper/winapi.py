import ctypes
from ctypes.wintypes import *

from defines import *

PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400


def open_process(pid: int) -> HANDLE:
    h_process = ctypes.windll.kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    return h_process


def read_process_memory(hProcess: HANDLE, offset: int, size: ctypes.c_size_t) -> bytes:
    buf = ctypes.create_string_buffer(size)
    ctypes.windll.kernel32.ReadProcessMemory(
        ctypes.cast(hProcess, ctypes.c_void_p),
        ctypes.cast(offset, ctypes.c_void_p),
        ctypes.cast(buf, ctypes.c_wchar_p),
        size,
        None,
    )
    return bytes(buf)


def virtual_query_ex(
    hProcess: HANDLE, offset: int, mbi: MEMORY_BASIC_INFORMATION
) -> ctypes.c_size_t:
    size = ctypes.windll.kernel32.VirtualQueryEx(
        ctypes.cast(hProcess, ctypes.c_void_p),
        ctypes.cast(offset, ctypes.c_void_p),
        ctypes.byref(mbi),
        ctypes.sizeof(mbi),
    )
    return size
