import argparse
import pathlib

import pefile
from defines import *
from winapi import *


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

    h_process = open_process(args.pid)
    mbi = MEMORY_BASIC_INFORMATION()
    offset = 0
    size = -1
    while size != 0:
        size = virtual_query_ex(h_process, offset, mbi)
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

        buf = read_process_memory(h_process, prev_offset, mbi.RegionSize)
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
