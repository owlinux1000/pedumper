# pedumper

pedumper can easily dump PE files within memory.

## Installation

```cmd
pip install pedumper
```

## How to use

```cmd
C:\Users\user\Desktop>pedumper -p 24532
[!] Found a PE file in the target memory
[*] Address     : 0x133f8e80000
[*] Region      : 0x133f8e80000 - 0x133f8eb7000
[*] Protect     : 0x40 (PAGE_EXECUTE_READWRITE)
[*] Type        : 0x20000 (MEM_PRIVATE)
[*] State       : 0x1000 (MEM_COMMIT)
[!] Saved the found PE to 0x133f8e80000.exe

[!] Found a PE file in the target memory
[*] Address     : 0x133f8e9b800
[*] Region      : 0x133f8e80000 - 0x133f8eb7000
[*] Protect     : 0x40 (PAGE_EXECUTE_READWRITE)
[*] Type        : 0x20000 (MEM_PRIVATE)
[*] State       : 0x1000 (MEM_COMMIT)
[!] Saved the found PE to 0x133f8e9b800.exe
```