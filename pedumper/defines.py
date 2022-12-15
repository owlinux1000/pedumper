from ctypes import Structure, c_size_t, c_void_p
from ctypes.wintypes import DWORD, WORD

# https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
STATE = {0x1000: "MEM_COMMIT", 0x2000: "MEM_RESERVE", 0x10000: "MEM_FREE"}
TYPE = {0x20000: "MEM_PRIVATE", 0x40000: "MEM_MAPPED", 0x100000: "MEM_IMAGE"}

# https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
PROTECT = {
    "PAGE_NOACCESS": 0x1,
    "PAGE_READONLY": 0x2,
    "PAGE_READWRITE": 0x4,
    "PAGE_EXECUTE": 0x10,
    "PAGE_EXECUTE_READ": 0x20,
    "PAGE_EXECUTE_READWRITE": 0x40,
}


class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = (
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", DWORD),
        ("PartitionId", WORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
    )
