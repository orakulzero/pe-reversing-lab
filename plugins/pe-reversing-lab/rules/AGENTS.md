# PE Reversing Lab Operational Rules

1. Always verify DOS `MZ` (`0x5A4D`) and `PE\0\0` signatures before parsing COFF and OptionalHeader structures.
2. Flag any PE section with Shannon entropy `>= 7.0` bits/byte as potentially packed or encrypted.
3. Map imported Windows APIs against the capability catalog (`anti_debug`, `process_injection`, `process_hollowing`, `privilege_escalation`).
4. Route lifecycle hooks through the single-process `agy-golden-stack` dispatcher.
