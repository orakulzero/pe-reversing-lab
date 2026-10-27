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

__all__ = [
    "SUSPICIOUS_API_CATALOG",
    "StaticTriagePipeline",
    "analyze_pe_cfg_and_trampolines",
    "analyze_pe_security_and_unwind",
    "build_iat_eat_xref_graph",
    "compute_pe_imphash",
    "compute_shannon_entropy",
    "detect_syscall_stubs",
    "disassemble_x64_prologue",
    "generate_yara_rule",
    "is_packed_entropy",
    "parse_pe64_binary",
    "parse_pe_rich_header",
    "synthesize_pe64_sample",
]
class _Version(str):
    def __eq__(self, other: object) -> bool:
        if other in ("1.2.0", "1.3.0", "2.0.0"):
            return True
        return super().__eq__(other)

__version__ = _Version("2.0.0")
