---
name: binary-analysis
description: "Autonomous static binary analysis skill for PE32+ x86_64 executables with anti-debug detection, section Shannon entropy assessment, IAT capability triage, and YARA rule generation."
---

# Static PE32+ x86_64 Reverse Engineering & YARA Synthesis

## Overview
Provides deterministic static triage for 64-bit Portable Executable (`PE32+` `x86_64`) binaries:
1. **COFF & OptionalHeader Inspection**: Validates `MZ` (`0x5A4D`), `PE\0\0`, `Machine=0x8664`, `Magic=0x20B`, `AddressOfEntryPoint`, and `ImageBase`.
2. **Section Entropy Analysis**: Computes Shannon entropy (`[0.0, 8.0]` bits/byte) per section and flags packed segments (`>= 7.0`).
3. **IAT Capability Mapping**: Detects anti-debug (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`) and injection primitives (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
4. **YARA Rule Synthesis**: Generates ready-to-run YARA rules anchored on `uint16(0) == 0x5A4D`, SHA-256 metadata, and API indicators.
