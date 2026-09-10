# MSI NTIOLib physical memory read PoC

This PoC demonstrates a physical memory disclosure in the signed `NTIOLib_X64.sys` version 3.0.0.17 shipped with MSI Center 2.0.73.0. The tested file has SHA-256 `95f6fad5832d0f115f4adeb56bafde43986d30546245e76bb69c220a301664db`.

The projects are independent:

- `target` allocates locked user pages, fills each page with a self-validating record, and waits. It has no driver code and does not write its address or process information to a file.
- `attacker` starts the target, opens `\\.\NTIOLib_CC_Clock`, completes the driver's handshake, reads the Windows physical RAM map, and scans accessible physical memory for the target record. It then reads and validates the complete page through the driver.

The attacker does not call `OpenProcess`, `ReadProcessMemory`, Toolhelp, PSAPI, or `NtQueryInformationProcess`. The process ID and text shown in the result come from the page read through the driver.

## Why the target allocates so much memory

The affected read path rejects physical addresses below 4 GB. The target uses `AllocateUserPhysicalPages` to request 4 GB of locked pages so that at least some target pages reliably land above that boundary in the 16 GB test VM. This makes the disclosure reproducible, but it is deliberately heavy and needs the lock-memory privilege inherited from an elevated launch.

## Build

Run each build script from a shell with MinGW-w64 available:

```sh
./target/build.sh
./attacker/build.sh
```

Copy `target/build/ntiolib_target.exe` to `C:\NtiolibLab\bin\ntiolib_target.exe`. Run `attacker/build/ntiolib_poc.exe` from an elevated console after the driver service is installed and running.

## Successful test

On Windows 11 build 26200.9168, the PoC found a target page at physical address `0x101832000`, recovered the target PID dynamically, read the target text, and passed the page verifier.

## Scope

The tested device is restricted to administrators and SYSTEM. A standard user received `STATUS_ACCESS_DENIED` for every tested access mode.

The current driver's useful primitive is arbitrary physical read for mapped addresses at or above 4 GB. On the test VM, the kernel process list roots and the page table roots needed for a general EPROCESS, PEB, module, and virtual address walk were below 4 GB. The driver could not read those roots, so this PoC does not claim a generic process or module API.
