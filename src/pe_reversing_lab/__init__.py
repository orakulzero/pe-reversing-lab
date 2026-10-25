"""
pe_reversing_lab
4-Tier (L1 -> L2 -> L3 -> L4) Static PE32+ x86_64 Reverse Engineering,
Section Entropy, IAT Anti-Debug Triage & YARA Rule Studio.
"""

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

__all__ = [
    "SUSPICIOUS_API_CATALOG",
    "StaticTriagePipeline",
    "build_iat_eat_xref_graph",
    "compute_shannon_entropy",
    "detect_syscall_stubs",
    "disassemble_x64_prologue",
    "generate_yara_rule",
    "is_packed_entropy",
    "parse_pe64_binary",
    "synthesize_pe64_sample",
]
__version__ = "1.2.0"
