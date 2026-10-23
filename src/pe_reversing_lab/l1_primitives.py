"""
src/pe_reversing_lab/l1_primitives.py
Tier L1 Atomic Primitives for Static PE32+ x86_64 Binary Analysis:
- Suspicious Windows API capability catalog (`SUSPICIOUS_API_CATALOG`)
- Exact Shannon entropy calculator (`compute_shannon_entropy`) and packer detector (`is_packed_entropy`)
- Pure-Python PE32+ x86_64 sample synthesizer (`synthesize_pe64_sample`) and structural parser (`parse_pe64_binary`)
- Automated YARA rule generator (`generate_yara_rule`)
"""

from __future__ import annotations

import datetime
import hashlib
import math
import re
import struct
from typing import Any, Dict, Iterable, List, Sequence, Tuple

SUSPICIOUS_API_CATALOG: Dict[str, Dict[str, Any]] = {
    "IsDebuggerPresent": {
        "category": "anti_debug",
        "severity_weight": 20,
        "description": "Queries PEB.BeingDebugged flag to detect user-mode debuggers.",
    },
    "CheckRemoteDebuggerPresent": {
        "category": "anti_debug",
        "severity_weight": 22,
        "description": "Queries kernel ProcessDebugPort to detect attached remote debuggers.",
    },
    "NtQueryInformationProcess": {
        "category": "anti_debug",
        "severity_weight": 25,
        "description": "Queries ProcessDebugPort / ProcessDebugFlags / ProcessDebugObjectHandle.",
    },
    "OutputDebugStringA": {
        "category": "anti_debug",
        "severity_weight": 12,
        "description": "Probes debugger presence via GetLastError side effects.",
    },
    "DebugActiveProcess": {
        "category": "anti_debug",
        "severity_weight": 18,
        "description": "Self-debugging or target process attachment primitive.",
    },
    "VirtualAllocEx": {
        "category": "process_injection",
        "severity_weight": 25,
        "description": "Allocates executable memory regions in a remote process.",
    },
    "WriteProcessMemory": {
        "category": "process_injection",
        "severity_weight": 25,
        "description": "Writes payload bytes into a remote process virtual address space.",
    },
    "CreateRemoteThread": {
        "category": "process_injection",
        "severity_weight": 28,
        "description": "Spawns execution thread inside a remote process.",
    },
    "QueueUserAPC": {
        "category": "process_injection",
        "severity_weight": 24,
        "description": "Queues asynchronous procedure call to a target thread for APC injection.",
    },
    "NtUnmapViewOfSection": {
        "category": "process_hollowing",
        "severity_weight": 26,
        "description": "Unmaps target image section during process hollowing.",
    },
    "RtlAdjustPrivilege": {
        "category": "privilege_escalation",
        "severity_weight": 22,
        "description": "Enables SeDebugPrivilege or other process token privileges.",
    },
    "SetWindowsHookExW": {
        "category": "input_capture",
        "severity_weight": 18,
        "description": "Installs global window/keyboard hook procedure.",
    },
}


def compute_shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits per byte ([0.0, 8.0])."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(float(entropy), 6)


def is_packed_entropy(entropy: float, threshold: float = 7.0) -> bool:
    """Return True when byte entropy meets or exceeds the packing threshold (default 7.0)."""
    return float(entropy) >= float(threshold)


def synthesize_pe64_sample(
    section_names: Sequence[str] = (".text", ".rdata"),
    imports: Sequence[str] = ("IsDebuggerPresent",),
    high_entropy_section: bool = False,
) -> bytes:
    """
    Construct a standards-compliant 64-bit PE32+ (`0x8664` AMD64, `0x20B` OptionalHeader)
    binary image in memory with valid `IMAGE_SECTION_HEADER` entries, import strings,
    and optional high-entropy (`8.0` bits/byte) packed section payload.
    """
    sec_list = list(section_names) if section_names else [".text"]
    e_lfanew = 0x80

    # DOS Header (128 bytes: 'MZ' at 0, e_lfanew at 0x3C)
    dos_header = bytearray(e_lfanew)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, e_lfanew)

    # PE Signature + COFF File Header (20 bytes)
    num_sections = len(sec_list)
    size_of_optional_header = 240  # standard PE32+ optional header size
    characteristics = 0x0022  # IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
    coff_header = struct.pack(
        "<4sHHIIIHH",
        b"PE\x00\x00",
        0x8664,  # IMAGE_FILE_MACHINE_AMD64
        num_sections,
        1729680000,
        0,
        0,
        size_of_optional_header,
        characteristics,
    )

    # Optional Header PE32+ (240 bytes)
    opt_header = bytearray(size_of_optional_header)
    entry_point_rva = 0x1000
    image_base = 0x140000000
    struct.pack_into("<H", opt_header, 0, 0x020B)  # PE32+ magic
    struct.pack_into("<I", opt_header, 16, entry_point_rva)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt_header, 24, image_base)  # ImageBase
    struct.pack_into("<I", opt_header, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_header, 36, 0x200)  # FileAlignment

    headers_end = e_lfanew + len(coff_header) + size_of_optional_header + (num_sections * 40)
    raw_offset = ((headers_end + 0x1FF) // 0x200) * 0x200

    section_headers = bytearray()
    section_blobs: List[bytes] = []
    current_raw_ptr = raw_offset

    import_blob = b"KERNEL32.dll\x00ntdll.dll\x00USER32.dll\x00" + b"\x00".join(
        imp.encode("ascii", errors="ignore") for imp in imports
    ) + b"\x00"

    for idx, sec_name in enumerate(sec_list):
        if high_entropy_section and idx == len(sec_list) - 1:
            # Uniform 0..255 distribution -> 8.000 bits/byte entropy
            repeat_block = bytes(range(256)) * 32
            payload = repeat_block + import_blob
        elif idx == 0:
            # Low-entropy code prologue + import table markers
            payload = (b"\x48\x89\x5c\x24\x08\x48\x83\xec\x20\x90\xc3" * 32) + b"\x00" * 128 + import_blob
        else:
            payload = import_blob + (b"\x00" * 256)

        aligned_size = ((len(payload) + 0x1FF) // 0x200) * 0x200
        padded_payload = payload.ljust(aligned_size, b"\x00") if not (high_entropy_section and idx == len(sec_list) - 1) else payload

        name_bytes = sec_name.encode("ascii", errors="ignore")[:8].ljust(8, b"\x00")
        virtual_size = len(padded_payload)
        virtual_addr = 0x1000 * (idx + 1)
        raw_size = len(padded_payload)
        sec_chars = 0x60000020 if idx == 0 else 0x40000040
        sec_hdr = struct.pack(
            "<8sIIIIIIHHI",
            name_bytes,
            virtual_size,
            virtual_addr,
            raw_size,
            current_raw_ptr,
            0,
            0,
            0,
            0,
            sec_chars,
        )
        section_headers.extend(sec_hdr)
        section_blobs.append(padded_payload)
        current_raw_ptr += raw_size

    prefix = bytes(dos_header) + coff_header + bytes(opt_header) + bytes(section_headers)
    padding = b"\x00" * (raw_offset - len(prefix))
    return prefix + padding + b"".join(section_blobs)


def parse_pe64_binary(data: bytes) -> Dict[str, Any]:
    """
    Parse a PE32+ x86_64 binary buffer, extracting COFF/OptionalHeader fields,
    per-section Shannon entropy, packing indicators, and suspicious IAT capabilities.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 0x100:
        raise ValueError("Invalid or truncated PE buffer (size < 256 bytes)")

    raw = bytes(data)
    if raw[:2] != b"MZ":
        raise ValueError("Missing DOS 'MZ' signature (0x5A4D)")

    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 24 > len(raw):
        raise ValueError(f"Invalid e_lfanew offset: {e_lfanew}")

    (
        pe_sig,
        machine,
        num_sections,
        timestamp,
        _sym_ptr,
        _num_syms,
        opt_hdr_size,
        _chars,
    ) = struct.unpack_from("<4sHHIIIHH", raw, e_lfanew)

    if pe_sig != b"PE\x00\x00":
        raise ValueError("Missing 'PE\\0\\0' signature at e_lfanew")

    opt_offset = e_lfanew + 24
    if opt_offset + opt_hdr_size > len(raw):
        raise ValueError("Truncated OptionalHeader")

    opt_magic = struct.unpack_from("<H", raw, opt_offset)[0]
    is_pe64 = opt_magic == 0x020B or machine == 0x8664
    entry_point_rva = struct.unpack_from("<I", raw, opt_offset + 16)[0]
    image_base = (
        struct.unpack_from("<Q", raw, opt_offset + 24)[0]
        if opt_magic == 0x020B
        else struct.unpack_from("<I", raw, opt_offset + 28)[0]
    )

    sec_table_offset = opt_offset + opt_hdr_size
    sections: List[Dict[str, Any]] = []
    any_section_packed = False

    for idx in range(num_sections):
        sh_off = sec_table_offset + idx * 40
        if sh_off + 40 > len(raw):
            break
        (
            raw_name,
            virtual_size,
            virtual_addr,
            raw_size,
            raw_ptr,
            _reloc_ptr,
            _line_ptr,
            _num_reloc,
            _num_line,
            sec_chars,
        ) = struct.unpack_from("<8sIIIIIIHHI", raw, sh_off)
        sec_name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        sec_slice = raw[raw_ptr : raw_ptr + raw_size] if raw_ptr + raw_size <= len(raw) else b""
        sec_entropy = compute_shannon_entropy(sec_slice)
        sec_packed = is_packed_entropy(sec_entropy)
        if sec_packed:
            any_section_packed = True
        sections.append(
            {
                "name": sec_name,
                "virtual_size": int(virtual_size),
                "virtual_address": int(virtual_addr),
                "raw_size": int(raw_size),
                "entropy": sec_entropy,
                "packed": sec_packed,
                "characteristics": hex(sec_chars),
            }
        )

    overall_entropy = compute_shannon_entropy(raw)
    packed = bool(any_section_packed or is_packed_entropy(overall_entropy))

    suspicious_apis: List[str] = []
    capabilities: List[Dict[str, Any]] = []
    for api_name, meta in SUSPICIOUS_API_CATALOG.items():
        if api_name.encode("ascii") in raw:
            suspicious_apis.append(api_name)
            capabilities.append(
                {
                    "api": api_name,
                    "category": meta["category"],
                    "severity_weight": meta["severity_weight"],
                    "description": meta["description"],
                }
            )

    sha256_hex = hashlib.sha256(raw).hexdigest()
    return {
        "format": "PE32+" if is_pe64 else "PE32",
        "architecture": "x86_64" if machine == 0x8664 else hex(machine),
        "machine": hex(machine),
        "sha256": sha256_hex,
        "size": len(raw),
        "timestamp": int(timestamp),
        "entry_point_rva": int(entry_point_rva),
        "image_base": int(image_base),
        "entropy": overall_entropy,
        "packed": packed,
        "sections": sections,
        "suspicious_apis": suspicious_apis,
        "capabilities": capabilities,
    }


def generate_yara_rule(
    rule_name: str,
    sha256: str,
    suspicious_apis: Iterable[str],
    packed: bool = False,
    score: int = 80,
) -> str:
    """Generate a YARA rule from static PE32+ indicators and suspicious API imports."""
    clean_hash = (sha256 or "").strip().lower()
    if not clean_hash:
        raise ValueError("sha256 must not be empty")

    safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", (rule_name or "auto_pe64_rule").strip())
    if not safe_name or safe_name[0].isdigit():
        safe_name = "rule_" + safe_name

    api_list = [str(a).strip() for a in (suspicious_apis or []) if str(a).strip()]
    date_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    string_lines = [
        f'        $hash_marker = "{clean_hash[:16]}" ascii wide',
    ]
    for idx, api in enumerate(api_list):
        string_lines.append(f'        $api_{idx} = "{api}" ascii wide')

    strings_block = "\n".join(string_lines)
    cond_parts = ["uint16(0) == 0x5A4D"]
    if api_list:
        cond_parts.append("any of ($api_*)")
    else:
        cond_parts.append("$hash_marker")
    condition_expr = " and ".join(cond_parts)

    return (
        f"rule {safe_name} {{\n"
        f"    meta:\n"
        f'        description = "Auto-generated PE32+ x86_64 signature for {clean_hash}"\n'
        f'        date = "{date_str}"\n'
        f'        sha256 = "{clean_hash}"\n'
        f"        packed = {str(bool(packed)).lower()}\n"
        f"        score = {int(score)}\n\n"
        f"    strings:\n"
        f"{strings_block}\n\n"
        f"    condition:\n"
        f"        {condition_expr}\n"
        f"}}\n"
    )
