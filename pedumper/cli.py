import argparse
import ctypes
import pathlib
import sys

import pefile

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
PROCESS_ALL_ACCESS = 0x1F0FFF


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """
    Ref: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
    typedef struct _MEMORY_BASIC_INFORMATION {
        PVOID  BaseAddress;
        PVOID  AllocationBase;
        DWORD  AllocationProtect;
        WORD   PartitionId;
        SIZE_T RegionSize;
        DWORD  State;
        DWORD  Protect;
        DWORD  Type;
    } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

    _fields_ = (
        ('BaseAddress', ctypes.c_ulonglong),
        ('AllocationBase', ctypes.c_ulonglong),
        ('AllocationProtect', ctypes.c_uint32),
        ('__alignment', ctypes.c_uint32),
        ('RegionSize', ctypes.c_ulonglong),
        ('State', ctypes.c_uint32),
        ('Protect', ctypes.c_uint32),
        ('Type', ctypes.c_uint32),
        ('__alignment2', ctypes.c_uint32)
    )
    """

    _fields_ = (
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32),
        ("PartitionId", ctypes.c_uint16),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32),
        ("Protect", ctypes.c_uint32),
        ("Type", ctypes.c_uint32),
    )


def init_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Dump PE files in the target memory",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-p",
        "--pid",
        required=True,
        type=int,
        default=argparse.SUPPRESS,
        help="specify a target PID",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=pathlib.Path.cwd(),
        type=str,
        help="specify a output directory",
    )
    return parser.parse_args()


def open_process(pid: int) -> int:
    hProcess = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if hProcess == 0:
        print(f"Failed to open the process: {pid}")
        sys.exit(1)

    return hProcess


def read_process_memory(hProcess: int, offset: int, size: ctypes.c_size_t) -> bytes:
    buf = ctypes.create_string_buffer(size)
    ctypes.windll.kernel32.ReadProcessMemory(
        ctypes.cast(hProcess, ctypes.c_void_p),
        ctypes.cast(offset, ctypes.c_void_p),
        ctypes.cast(buf, ctypes.c_wchar_p),
        size,
        None,
    )
    return bytes(buf)


def extract_valid_pe(buf: bytes) -> bytes:
    mz_offset = 0
    trimmed_pe = b""
    while mz_offset != -1:
        mz_offset = buf.find(b"MZ", mz_offset)
        try:
            pe = pefile.PE(data=buf[mz_offset:])
            trimmed_pe = pe.trim()
            prev_mz_offset = mz_offset
            mz_offset += len(trimmed_pe)
        except pefile.PEFormatError:
            if mz_offset == -1:
                continue
            else:
                mz_offset += 2
                continue
        yield (prev_mz_offset, trimmed_pe)


def main():
    args = init_args()
    hProcess = open_process(args.pid)
    offset = 0
    ret = -1
    while ret != 0:
        mbi = MEMORY_BASIC_INFORMATION()
        ret = ctypes.windll.kernel32.VirtualQueryEx(
            ctypes.cast(hProcess, ctypes.c_void_p),
            ctypes.cast(offset, ctypes.c_void_p),
            ctypes.byref(mbi),
            ctypes.sizeof(MEMORY_BASIC_INFORMATION),
        )
        prev_offset = offset
        if mbi.BaseAddress is not None:
            offset = mbi.BaseAddress
        offset += mbi.RegionSize

        if mbi.Protect == PROTECT["PAGE_NOACCESS"]:
            continue
        if mbi.Protect == PROTECT["PAGE_READONLY"]:
            continue

        # To avoid reading a large memory
        if mbi.RegionSize >= 2**32:
            continue

        buf = read_process_memory(hProcess, prev_offset, mbi.RegionSize)
        for mz_offset, pe_buf in extract_valid_pe(buf):

            protect = [k for k, v in PROTECT.items() if v == mbi.Protect][0]
            print("[!] Found a PE file in the target memory")
            print(f"[*] Address\t: {hex(prev_offset + mz_offset)}")
            print(
                f"[*] Region\t: {hex(prev_offset)} - {hex(prev_offset + mbi.RegionSize)}"
            )
            print(f"[*] Protect\t: {hex(mbi.Protect)} ({protect})")
            print(f"[*] Type\t: {hex(mbi.Type)} ({TYPE[mbi.Type]})")
            print(f"[*] State\t: {hex(mbi.State)} ({STATE[mbi.State]})")

            dumped_filename = f"{hex(prev_offset + mz_offset)}.exe"
            try:
                with open(dumped_filename, "wb") as fout:
                    fout.write(pe_buf)
                    print(f"[!] Saved the found PE to {dumped_filename}\n")
            except Exception as e:
                print(f"Failed to save the found PE: {e}\n")


if __name__ == "__main__":
    main()
