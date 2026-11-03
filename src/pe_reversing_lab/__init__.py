"""
pe_reversing_lab
4-Tier (L1 -> L2 -> L3 -> L4) Static PE32+ x86_64 Reverse Engineering,
Section Entropy, IAT Anti-Debug Triage & YARA Rule Studio.
"""

from pe_reversing_lab.analyzer import (
    analyze_pe_cfg_and_trampolines,
    analyze_pe_security_and_unwind,
    compute_pe_imphash,
    parse_pe_rich_header,
)
from pe_reversing_lab.l1_primitives import (
    SUSPICIOUS_API_CATALOG,
    build_iat_eat_xref_graph,
    compute_shannon_entropy,
    detect_syscall_stubs,
    disassemble_x64_prologue,
    generate_yara_rule,
    is_packed_entropy,
    parse_pe64_binary,
    synthesize_pe64_sample,
)
from pe_reversing_lab.l3_pipeline import StaticTriagePipeline
from pe_reversing_lab.local_ipc_packet_sniffer import (
    LocalIpcPacketSniffer,
    inspect_ipc_packet,
)
from pe_reversing_lab.pe64_imphash_iat_guard import (
    PE64ImpHashIATGuard,
    audit_pe64_import_integrity,
    compute_canonical_imphash,
    detect_dynamic_iat_resolution,
)

__all__ = [
    "LocalIpcPacketSniffer",
    "PE64ImpHashIATGuard",
    "SUSPICIOUS_API_CATALOG",
    "StaticTriagePipeline",
    "analyze_pe_cfg_and_trampolines",
    "analyze_pe_security_and_unwind",
    "audit_pe64_import_integrity",
    "build_iat_eat_xref_graph",
    "compute_canonical_imphash",
    "compute_pe_imphash",
    "compute_shannon_entropy",
    "detect_dynamic_iat_resolution",
    "detect_syscall_stubs",
    "disassemble_x64_prologue",
    "generate_yara_rule",
    "inspect_ipc_packet",
    "is_packed_entropy",
    "parse_pe64_binary",
    "parse_pe_rich_header",
    "synthesize_pe64_sample",
]
__version__ = "2.0.0"
__v3_generation__ = "3.0.0"
