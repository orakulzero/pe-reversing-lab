"""
pe_reversing_lab
4-Tier (L1 -> L2 -> L3 -> L4) Static PE32+ x86_64 Reverse Engineering,
Section Entropy, IAT Anti-Debug Triage & YARA Rule Studio.
"""

from pe_reversing_lab.l1_primitives import (
    SUSPICIOUS_API_CATALOG,
    compute_shannon_entropy,
    generate_yara_rule,
    is_packed_entropy,
    parse_pe64_binary,
    synthesize_pe64_sample,
)
from pe_reversing_lab.l3_pipeline import StaticTriagePipeline

__all__ = [
    "SUSPICIOUS_API_CATALOG",
    "StaticTriagePipeline",
    "compute_shannon_entropy",
    "generate_yara_rule",
    "is_packed_entropy",
    "parse_pe64_binary",
    "synthesize_pe64_sample",
]
__version__ = "1.0.0"
