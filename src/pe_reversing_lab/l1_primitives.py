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


def parse_rich_header(data: bytes, e_lfanew: int) -> Dict[str, Any]:
    """
    Search DOS stub (0x40..e_lfanew) for b'Rich' marker, extract XOR key,
    locate b'DanS', and decode @comp.id compiler/linker records.
    """
    empty_result: Dict[str, Any] = {
        "present": False,
        "xor_key": "0x0",
        "dans_offset": 0,
        "rich_offset": 0,
        "record_count": 0,
        "records": [],
        "rich_hash": "",
    }
    if not isinstance(data, (bytes, bytearray)) or len(data) < 0x48 or e_lfanew <= 0x40:
        return empty_result

    search_limit = min(len(data), e_lfanew)
    rich_idx = data.find(b"Rich", 0x40, search_limit)
    if rich_idx == -1 or rich_idx + 8 > len(data):
        return empty_result

    xor_key = struct.unpack_from("<I", data, rich_idx + 4)[0]
    dans_idx = -1
    for off in range(rich_idx - 4, 0x3C, -4):
        val = struct.unpack_from("<I", data, off)[0] ^ xor_key
        if val == 0x536E6144:  # b"DanS"
            dans_idx = off
            break

    if dans_idx == -1:
        return {
            "present": False,
            "xor_key": hex(xor_key),
            "dans_offset": 0,
            "rich_offset": rich_idx,
            "record_count": 0,
            "records": [],
            "rich_hash": "",
        }

    decrypted = bytearray()
    for off in range(dans_idx, rich_idx, 4):
        val = struct.unpack_from("<I", data, off)[0] ^ xor_key
        decrypted.extend(struct.pack("<I", val))

    records: List[Dict[str, int]] = []
    # After DanS (4 bytes) + 3 zero padding DWORDs (12 bytes) = 16 bytes:
    for i in range(16, len(decrypted), 8):
        if i + 8 <= len(decrypted):
            comp_id = struct.unpack_from("<I", decrypted, i)[0]
            count = struct.unpack_from("<I", decrypted, i + 4)[0]
            prod_id = comp_id >> 16
            build_id = comp_id & 0xFFFF
            records.append({
                "prod_id": int(prod_id),
                "build_id": int(build_id),
                "count": int(count),
            })

    rich_hash = hashlib.md5(decrypted).hexdigest()
    return {
        "present": True,
        "xor_key": hex(xor_key),
        "dans_offset": dans_idx,
        "rich_offset": rich_idx,
        "record_count": len(records),
        "records": records,
        "rich_hash": rich_hash,
    }


def parse_export_directory(
    data: bytes,
    opt_offset: int,
    sections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Parse IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) from DataDirectory at opt_offset + 112.
    Translates RVAs using section table and extracts exported function names, ordinals, and RVAs.
    """
    empty_result: Dict[str, Any] = {
        "present": False,
        "export_rva": 0,
        "export_size": 0,
        "dll_name": "",
        "function_count": 0,
        "exports": [],
    }
    if not isinstance(data, (bytes, bytearray)) or opt_offset + 120 > len(data):
        return empty_result

    export_rva, export_size = struct.unpack_from("<II", data, opt_offset + 112)
    if export_rva == 0 or export_size == 0:
        return empty_result

    def rva_to_offset(rva: int) -> Optional[int]:
        for sec in sections:
            virt_addr = sec.get("virtual_address", 0)
            span = max(sec.get("virtual_size", 0), sec.get("raw_size", 0))
            if virt_addr <= rva < virt_addr + span:
                raw_ptr = sec.get("raw_ptr", sec.get("raw_offset", 0))
                return raw_ptr + (rva - virt_addr)
        return None

    export_off = rva_to_offset(export_rva)
    if export_off is None or export_off + 40 > len(data):
        return {
            "present": True,
            "export_rva": int(export_rva),
            "export_size": int(export_size),
            "dll_name": "",
            "function_count": 0,
            "exports": [],
        }

    (
        _exp_chars,
        _exp_ts,
        _major,
        _minor,
        name_rva,
        ordinal_base,
        num_funcs,
        num_names,
        addr_funcs_rva,
        addr_names_rva,
        addr_ords_rva,
    ) = struct.unpack_from("<IIHHIIIIIII", data, export_off)

    dll_name = ""
    name_off = rva_to_offset(name_rva)
    if name_off is not None and name_off < len(data):
        dll_name = data[name_off:].split(b"\x00", 1)[0].decode("ascii", errors="replace")

    names_off = rva_to_offset(addr_names_rva)
    ords_off = rva_to_offset(addr_ords_rva)
    funcs_off = rva_to_offset(addr_funcs_rva)

    exports: List[Dict[str, Any]] = []
    if names_off is not None and ords_off is not None and funcs_off is not None:
        count_to_parse = min(int(num_names), 5000)
        for i in range(count_to_parse):
            if names_off + i * 4 + 4 > len(data) or ords_off + i * 2 + 2 > len(data):
                break
            n_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
            n_off = rva_to_offset(n_rva)
            fn_name = ""
            if n_off is not None and n_off < len(data):
                fn_name = data[n_off:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            ord_idx = struct.unpack_from("<H", data, ords_off + i * 2)[0]
            f_rva = 0
            if funcs_off + ord_idx * 4 + 4 <= len(data):
                f_rva = struct.unpack_from("<I", data, funcs_off + ord_idx * 4)[0]
            exports.append({
                "name": fn_name,
                "ordinal": int(ordinal_base + ord_idx),
                "rva": hex(f_rva),
            })

    return {
        "present": True,
        "export_rva": int(export_rva),
        "export_size": int(export_size),
        "dll_name": dll_name,
        "function_count": int(num_funcs),
        "exports": exports,
    }


def parse_tls_directory(
    data: bytes,
    opt_offset: int,
    image_base: int,
    sections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Parse IMAGE_DIRECTORY_ENTRY_TLS (index 9) from DataDirectory at opt_offset + 184.
    Extracts IMAGE_TLS_DIRECTORY64 and walks the null-terminated array of callback VAs.
    """
    empty_result: Dict[str, Any] = {
        "present": False,
        "tls_rva": 0,
        "tls_size": 0,
        "callbacks_va": "0x0",
        "callback_count": 0,
        "callbacks": [],
    }
    if not isinstance(data, (bytes, bytearray)) or opt_offset + 192 > len(data):
        return empty_result

    tls_rva, tls_size = struct.unpack_from("<II", data, opt_offset + 184)
    if tls_rva == 0 or tls_size == 0:
        return empty_result

    def rva_to_offset(rva: int) -> Optional[int]:
        for sec in sections:
            virt_addr = sec.get("virtual_address", 0)
            span = max(sec.get("virtual_size", 0), sec.get("raw_size", 0))
            if virt_addr <= rva < virt_addr + span:
                raw_ptr = sec.get("raw_ptr", sec.get("raw_offset", 0))
                return raw_ptr + (rva - virt_addr)
        return None

    tls_off = rva_to_offset(tls_rva)
    if tls_off is None or tls_off + 40 > len(data):
        return {
            "present": True,
            "tls_rva": int(tls_rva),
            "tls_size": int(tls_size),
            "callbacks_va": "0x0",
            "callback_count": 0,
            "callbacks": [],
        }

    _start_va, _end_va, _index_va, callbacks_va, _zero_fill, _chars = struct.unpack_from(
        "<QQQQII", data, tls_off
    )
    callbacks: List[Dict[str, str]] = []
    if callbacks_va != 0:
        cb_rva = callbacks_va - image_base
        cb_off = rva_to_offset(cb_rva)
        if cb_off is not None:
            curr = cb_off
            while curr + 8 <= len(data) and len(callbacks) < 256:
                cb_val = struct.unpack_from("<Q", data, curr)[0]
                if cb_val == 0:
                    break
                callbacks.append({
                    "va": hex(cb_val),
                    "rva": hex(cb_val - image_base),
                })
                curr += 8

    return {
        "present": True,
        "tls_rva": int(tls_rva),
        "tls_size": int(tls_size),
        "callbacks_va": hex(callbacks_va),
        "callback_count": len(callbacks),
        "callbacks": callbacks,
    }


def detect_trailing_overlay(
    data: bytes,
    sections: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Calculate maximum raw section end. If len(data) > max_section_end, extract
    overlay bytes, Shannon entropy, and SHA-256.
    """
    if not sections or not isinstance(data, (bytes, bytearray)):
        return {
            "present": False,
            "overlay_offset": 0,
            "overlay_size": 0,
            "entropy": 0.0,
            "sha256": "",
        }

    max_end = 0
    for sec in sections:
        raw_ptr = sec.get("raw_ptr", sec.get("raw_offset", 0))
        raw_size = sec.get("raw_size", 0)
        end_pos = raw_ptr + raw_size
        if end_pos > max_end:
            max_end = end_pos

    if len(data) > max_end:
        overlay_bytes = data[max_end:]
        return {
            "present": True,
            "overlay_offset": max_end,
            "overlay_size": len(overlay_bytes),
            "entropy": compute_shannon_entropy(overlay_bytes),
            "sha256": hashlib.sha256(overlay_bytes).hexdigest(),
        }

    return {
        "present": False,
        "overlay_offset": 0,
        "overlay_size": 0,
        "entropy": 0.0,
        "sha256": "",
    }


def detect_rwx_sections(sections: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Inspect characteristics of all sections for IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE (0xA0000000).
    """
    rwx_sections: List[str] = []
    for sec in sections:
        raw_chars = sec.get("characteristics", "0x0")
        if isinstance(raw_chars, str):
            chars_val = int(raw_chars, 16)
        else:
            chars_val = int(raw_chars)
        if (chars_val & 0xA0000000) == 0xA0000000:
            rwx_sections.append(sec.get("name", ""))

    return {
        "has_rwx": bool(rwx_sections),
        "rwx_count": len(rwx_sections),
        "rwx_sections": rwx_sections,
    }


def synthesize_pe64_sample(
    section_names: Sequence[str] = (".text", ".rdata"),
    imports: Sequence[str] = ("IsDebuggerPresent",),
    high_entropy_section: bool = False,
    with_rich_header: bool = False,
    with_export_table: bool = False,
    with_tls_directory: bool = False,
    overlay_bytes: Optional[bytes] = None,
    rwx_section: bool = False,
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

    if with_rich_header:
        # Synthesize DanS .. Rich block in DOS stub (0x40..0x70)
        xor_key = 0xA4531774
        comp_records = [
            ((147 << 16) | 30729, 94),
            ((260 << 16) | 33145, 11),
        ]
        dans_clear = bytearray()
        dans_clear.extend(b"DanS")
        dans_clear.extend(b"\x00" * 12)  # 3 zero dwords
        for cid, cnt in comp_records:
            dans_clear.extend(struct.pack("<II", cid, cnt))

        # Encrypt with xor_key
        dans_enc = bytearray()
        for off in range(0, len(dans_clear), 4):
            val = struct.unpack_from("<I", dans_clear, off)[0] ^ xor_key
            dans_enc.extend(struct.pack("<I", val))

        dos_header[0x40 : 0x40 + len(dans_enc)] = dans_enc
        rich_off = 0x40 + len(dans_enc)
        dos_header[rich_off : rich_off + 4] = b"Rich"
        struct.pack_into("<I", dos_header, rich_off + 4, xor_key)

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

    if with_export_table and len(sec_list) >= 2:
        # Point Export directory to RVA 0x2000, size 128
        struct.pack_into("<II", opt_header, 112, 0x2000, 128)

    if with_tls_directory and len(sec_list) >= 2:
        # Point TLS directory to RVA 0x2080, size 40
        struct.pack_into("<II", opt_header, 184, 0x2080, 40)

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
            repeat_block = bytes(range(256)) * 32
            payload = repeat_block + import_blob
        elif idx == 0:
            payload = (b"\x48\x89\x5c\x24\x08\x48\x83\xec\x20\x90\xc3" * 32) + b"\x00" * 128 + import_blob
        else:
            payload = import_blob + (b"\x00" * 256)

        if idx == 1 and with_export_table:
            # Build mini export table inside section 2 (RVA 0x2000)
            exp_table = struct.pack(
                "<IIHHIIIIIII",
                0, 1729680000, 1, 0,
                0x2030,  # name_rva -> "TestModule.dll"
                1,       # ordinal_base
                1,       # num_funcs
                1,       # num_names
                0x2050,  # addr_funcs_rva
                0x2060,  # addr_names_rva
                0x2080,  # addr_ords_rva
            )
            mod_name = b"TestModule.dll\x00"
            func_rva_bytes = struct.pack("<I", 0x1000)
            func_name = b"SampleExportedFn\x00"
            func_name_rva = struct.pack("<I", 0x2064)
            ord_bytes = struct.pack("<H", 0)

            extra_blob = bytearray(256)
            extra_blob[0 : len(exp_table)] = exp_table
            extra_blob[0x30 : 0x30 + len(mod_name)] = mod_name
            extra_blob[0x50 : 0x54] = func_rva_bytes
            extra_blob[0x60 : 0x64] = func_name_rva
            extra_blob[0x64 : 0x64 + len(func_name)] = func_name
            extra_blob[0x80 : 0x82] = ord_bytes
            payload = bytes(extra_blob) + payload

        aligned_size = ((len(payload) + 0x1FF) // 0x200) * 0x200
        padded_payload = payload.ljust(aligned_size, b"\x00") if not (high_entropy_section and idx == len(sec_list) - 1) else payload

        name_bytes = sec_name.encode("ascii", errors="ignore")[:8].ljust(8, b"\x00")
        virtual_size = len(padded_payload)
        virtual_addr = 0x1000 * (idx + 1)
        raw_size = len(padded_payload)

        if rwx_section and idx == 0:
            sec_chars = 0xE0000020  # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        elif idx == 0:
            sec_chars = 0x60000020
        else:
            sec_chars = 0x40000040

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
    base_pe = prefix + padding + b"".join(section_blobs)
    if overlay_bytes:
        base_pe += overlay_bytes
    return base_pe


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
                "raw_ptr": int(raw_ptr),
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

    rich_info = parse_rich_header(raw, e_lfanew)
    export_info = parse_export_directory(raw, opt_offset, sections)
    tls_info = parse_tls_directory(raw, opt_offset, int(image_base), sections)
    overlay_info = detect_trailing_overlay(raw, sections)
    rwx_info = detect_rwx_sections(sections)

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
        "rich_header": rich_info,
        "exports": export_info,
        "tls": tls_info,
        "overlay": overlay_info,
        "rwx_anomaly": rwx_info,
    }


def generate_yara_rule(
    rule_name: str,
    sha256: str,
    suspicious_apis: Iterable[str],
    packed: bool = False,
    score: int = 80,
    rich_hash: Optional[str] = None,
    has_tls_callbacks: bool = False,
    has_overlay: bool = False,
    has_rwx: bool = False,
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

    if rich_hash:
        string_lines.append(f'        $rich_hash = "{rich_hash}" ascii wide')
    if has_tls_callbacks:
        string_lines.append('        $tls_marker = "TLS_CALLBACK" ascii wide')
    if has_overlay:
        string_lines.append('        $overlay_marker = "TRAILING_OVERLAY" ascii wide')
    if has_rwx:
        string_lines.append('        $rwx_anomaly = "RWX_SECTION" ascii wide')

    strings_block = "\n".join(string_lines)
    cond_parts = ["uint16(0) == 0x5A4D"]
    if api_list:
        cond_parts.append("any of ($api_*)")
    else:
        cond_parts.append("$hash_marker")
    condition_expr = " and ".join(cond_parts)

    meta_lines = [
        f'        description = "Auto-generated PE32+ x86_64 signature for {clean_hash}"',
        f'        date = "{date_str}"',
        f'        sha256 = "{clean_hash}"',
        f"        packed = {str(bool(packed)).lower()}",
        f"        score = {int(score)}",
    ]
    if rich_hash:
        meta_lines.append(f'        rich_hash = "{rich_hash}"')
    if has_tls_callbacks:
        meta_lines.append("        has_tls_callbacks = true")
    if has_overlay:
        meta_lines.append("        has_overlay = true")
    if has_rwx:
        meta_lines.append("        has_rwx = true")

    meta_block = "\n".join(meta_lines)

    return (
        f"rule {safe_name} {{\n"
        f"    meta:\n"
        f"{meta_block}\n\n"
        f"    strings:\n"
        f"{strings_block}\n\n"
        f"    condition:\n"
        f"        {condition_expr}\n"
        f"}}\n"
    )
