# PE Reversing Lab (`pe-reversing-lab`)

4-Tier (`L1 -> L2 -> L3 -> L4`) Static PE32+ x86_64 Reverse Engineering, Section Shannon Entropy Scanner, IAT Anti-Debug & Process Injection Triage, and YARA Rule Studio.

## 4-Tier Architecture

1. **Tier `L1` (`pe_reversing_lab.l1_primitives` + `.agents/skills/binary-analysis/`)**:
   - **Pure-Python PE32+ x86_64 Parser & Synthesizer (`parse_pe64_binary`, `synthesize_pe64_sample`)**: Parses DOS `MZ` (`0x5A4D`), `PE\0\0`, COFF (`Machine=0x8664`), `OptionalHeader` (`0x20B`), and `IMAGE_SECTION_HEADER` tables with zero native C dependencies.
   - **Shannon Entropy & Packer Detection (`compute_shannon_entropy`, `is_packed_entropy`)**: Exact `[0.0, 8.0]` bits/byte calculation flagging packed/encrypted sections (`>= 7.0`).
   - **Suspicious IAT Capability Catalog (`SUSPICIOUS_API_CATALOG`)**: Maps 12 high-signal Windows APIs (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `QueueUserAPC`, `NtUnmapViewOfSection`, `RtlAdjustPrivilege`, `SetWindowsHookExW`) across capability classes.
   - **Automated YARA Rule Generator (`generate_yara_rule`)**: Synthesizes ready-to-run YARA rules with SHA-256 metadata and `uint16(0) == 0x5A4D` conditions.

2. **Tier `L2` (`plugins/pe-reversing-lab/`)**:
   - Native plugin bundle with `<64`-char MCP tools (`pe_reversing_lab_triage_binary`, `pe_reversing_lab_generate_yara`) and single-process `agy-golden-stack` hook consolidation.

3. **Tier `L3` (`pe_reversing_lab.l3_pipeline.StaticTriagePipeline`)**:
   - 5-Stage deterministic binary triage FSM (`STAGE_1_PE64_HEADER_PARSE -> STAGE_2_SECTION_ENTROPY_SCAN -> STAGE_3_IAT_CAPABILITY_TRIAGE -> STAGE_4_YARA_RULE_SYNTHESIS -> STAGE_5_THREAT_SCORE_SEAL`) with cryptographic SHA-256 sealing.

4. **Tier `L4` (`pe_reversing_lab.l4_app.app`)**:
   - Standalone FastAPI + Tailwind Web Workstation (`GET /`, `GET /api/pe/catalog`, `POST /api/pe/triage`, `POST /api/pe/yara`, `POST /api/pe/report-to-root`) with direct cross-L4 telemetry reporting to `AGY Mission Control`.
