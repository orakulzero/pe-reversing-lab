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
from typing import Any
from collections.abc import Iterable, Sequence

SUSPICIOUS_API_CATALOG: dict[str, dict[str, Any]] = {
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


def parse_rich_header(data: bytes, e_lfanew: int) -> dict[str, Any]:
    """
    Search DOS stub (0x40..e_lfanew) for b'Rich' marker, extract XOR key,
    locate b'DanS', and decode @comp.id compiler/linker records.
    """
    empty_result: dict[str, Any] = {
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

    records: list[dict[str, int]] = []
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
    sections: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Parse IMAGE_DIRECTORY_ENTRY_EXPORT (index 0) from DataDirectory at opt_offset + 112.
    Translates RVAs using section table and extracts exported function names, ordinals, and RVAs.
    """
    empty_result: dict[str, Any] = {
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

    exports: list[dict[str, Any]] = []
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
    sections: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Parse IMAGE_DIRECTORY_ENTRY_TLS (index 9) from DataDirectory at opt_offset + 184.
    Extracts IMAGE_TLS_DIRECTORY64 and walks the null-terminated array of callback VAs.
    """
    empty_result: dict[str, Any] = {
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
    callbacks: list[dict[str, str]] = []
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
    sections: list[dict[str, Any]],
) -> dict[str, Any]:
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


def detect_rwx_sections(sections: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Inspect characteristics of all sections for IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE (0xA0000000).
    """
    rwx_sections: list[str] = []
    for sec in sections:
        raw_chars = sec.get("characteristics", "0x0")
        chars_val = int(raw_chars, 16) if isinstance(raw_chars, str) else int(raw_chars)
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
    inject_syscall_stub: bool = False,
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
        # Point Import directory to RVA 0x2100, size 40
        struct.pack_into("<II", opt_header, 120, 0x2100, 40)

    if with_tls_directory and len(sec_list) >= 2:
        # Point TLS directory to RVA 0x2080, size 40
        struct.pack_into("<II", opt_header, 184, 0x2080, 40)

    headers_end = e_lfanew + len(coff_header) + size_of_optional_header + (num_sections * 40)
    raw_offset = ((headers_end + 0x1FF) // 0x200) * 0x200

    section_headers = bytearray()
    section_blobs: list[bytes] = []
    current_raw_ptr = raw_offset

    import_blob = b"KERNEL32.dll\x00ntdll.dll\x00USER32.dll\x00" + b"\x00".join(
        imp.encode("ascii", errors="ignore") for imp in imports
    ) + b"\x00"

    for idx, sec_name in enumerate(sec_list):
        if high_entropy_section and idx == len(sec_list) - 1:
            repeat_block = bytes(range(256)) * 32
            payload = repeat_block + import_blob
        elif idx == 0:
            stub = b"\x4c\x8b\xd1\xb8\x18\x00\x00\x00\x0f\x05\xc3" if inject_syscall_stub else b""
            call_disp = -(len(stub) + 5)
            call_insn = b"\xe8" + struct.pack("<i", call_disp)
            iat_curr_rva = 0x1000 + len(stub) + 5
            iat_disp = 0x2180 - (iat_curr_rva + 6)
            iat_call_insn = b"\xff\x15" + struct.pack("<i", iat_disp) if with_export_table else b""
            payload = stub + call_insn + iat_call_insn + (b"\x48\x89\x5c\x24\x08\x48\x83\xec\x20\x90\xc3" * 32) + b"\x00" * 128 + import_blob
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

            extra_blob = bytearray(512)
            extra_blob[0 : len(exp_table)] = exp_table
            extra_blob[0x30 : 0x30 + len(mod_name)] = mod_name
            extra_blob[0x50 : 0x54] = func_rva_bytes
            extra_blob[0x60 : 0x64] = func_name_rva
            extra_blob[0x64 : 0x64 + len(func_name)] = func_name
            extra_blob[0x80 : 0x82] = ord_bytes

            # Mini Import Directory at RVA 0x2100 (offset 0x100 in section 2)
            imp_desc = struct.pack("<IIIII", 0x2140, 0, 0, 0x2160, 0x2180)
            extra_blob[0x100 : 0x100 + 20] = imp_desc
            struct.pack_into("<QQ", extra_blob, 0x140, 0x2170, 0)
            dll_str = b"KERNEL32.dll\x00"
            extra_blob[0x160 : 0x160 + len(dll_str)] = dll_str
            imp_by_name = struct.pack("<H", 0) + b"VirtualAlloc\x00"
            extra_blob[0x170 : 0x170 + len(imp_by_name)] = imp_by_name
            struct.pack_into("<QQ", extra_blob, 0x180, 0x2170, 0)

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


def parse_pe64_binary(data: bytes) -> dict[str, Any]:
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
    sections: list[dict[str, Any]] = []
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

    suspicious_apis: list[str] = []
    capabilities: list[dict[str, Any]] = []
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


def disassemble_x64_prologue(
    data: bytes,
    base_rva: int = 0x1000,
    max_instructions: int = 32,
    max_bytes: int = 128,
    stop_on_ret: bool = True,
) -> list[dict[str, Any]]:
    """
    Deterministic byte-level x86_64 prologue and stub instruction decoder.
    Decodes stack frame setup/teardown, register saves/restores, syscall setups,
    RIP-relative calls/jumps, relative branches, zeroing idioms, NOPs, and returns.
    """
    if not isinstance(data, (bytes, bytearray)):
        return []

    raw = bytes(data)
    instructions: list[dict[str, Any]] = []
    idx = 0
    limit = min(len(raw), max_bytes)

    reg_names_64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
    ext_regs_64 = ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

    while idx < limit and len(instructions) < max_instructions:
        curr_rva = base_rva + idx
        b0 = raw[idx]

        # 1. NOP (0x90)
        if b0 == 0x90:
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 1, "bytes": "90", "mnemonic": "nop", "operands": "",
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 1
            continue

        # 2. RET (0xC3)
        if b0 == 0xC3:
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 1, "bytes": "c3", "mnemonic": "ret", "operands": "",
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 1
            if stop_on_ret:
                break
            continue

        # 3. RET imm16 (0xC2 <imm16>)
        if b0 == 0xC2 and idx + 2 < limit:
            imm = struct.unpack_from("<H", raw, idx + 1)[0]
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 3, "bytes": raw[idx:idx+3].hex(" "), "mnemonic": "ret",
                "operands": hex(imm), "target_rva": None, "target_rva_hex": None,
            })
            idx += 3
            if stop_on_ret:
                break
            continue

        # 4. INT3 (0xCC)
        if b0 == 0xCC:
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 1, "bytes": "cc", "mnemonic": "int3", "operands": "",
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 1
            continue

        # 5. Multi-byte NOPs (0x0F 0x1F ...)
        if b0 == 0x0F and idx + 1 < limit and raw[idx + 1] == 0x1F:
            if idx + 7 < limit and raw[idx : idx + 8] == b"\x0f\x1f\x84\x00\x00\x00\x00\x00":
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 8, "bytes": raw[idx:idx+8].hex(" "), "mnemonic": "nop",
                    "operands": "dword ptr [rax+rax]", "target_rva": None, "target_rva_hex": None,
                })
                idx += 8
                continue
            if idx + 4 < limit and raw[idx : idx + 5] == b"\x0f\x1f\x44\x00\x00":
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 5, "bytes": raw[idx:idx+5].hex(" "), "mnemonic": "nop",
                    "operands": "dword ptr [rax+rax]", "target_rva": None, "target_rva_hex": None,
                })
                idx += 5
                continue
            if idx + 3 < limit and raw[idx : idx + 4] == b"\x0f\x1f\x40\x00":
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 4, "bytes": raw[idx:idx+4].hex(" "), "mnemonic": "nop",
                    "operands": "dword ptr [rax]", "target_rva": None, "target_rva_hex": None,
                })
                idx += 4
                continue
            if idx + 2 < limit and raw[idx : idx + 3] == b"\x0f\x1f\x00":
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 3, "bytes": raw[idx:idx+3].hex(" "), "mnemonic": "nop",
                    "operands": "word ptr [rax]", "target_rva": None, "target_rva_hex": None,
                })
                idx += 3
                continue

        # 6. Syscall (0x0F 0x05)
        if b0 == 0x0F and idx + 1 < limit and raw[idx + 1] == 0x05:
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 2, "bytes": "0f 05", "mnemonic": "syscall", "operands": "",
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 2
            continue

        # 7. INT 0x2E (0xCD 0x2E)
        if b0 == 0xCD and idx + 1 < limit and raw[idx + 1] == 0x2E:
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 2, "bytes": "cd 2e", "mnemonic": "int", "operands": "0x2e",
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 2
            continue

        # 8. UserSharedData probe (F6 04 25 08 03 FE 7F 01)
        if b0 == 0xF6 and idx + 7 < limit and raw[idx : idx + 8] == b"\xf6\x04\x25\x08\x03\xfe\x7f\x01":
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 8, "bytes": raw[idx:idx+8].hex(" "), "mnemonic": "test",
                "operands": "byte ptr [0x7ffe0308], 0x1", "target_rva": None, "target_rva_hex": None,
            })
            idx += 8
            continue

        # 9. Push rax..rdi (0x50..0x57)
        if 0x50 <= b0 <= 0x57:
            reg = reg_names_64[b0 - 0x50]
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 1, "bytes": hex(b0)[2:], "mnemonic": "push", "operands": reg,
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 1
            continue

        # 10. Pop rax..rdi (0x58..0x5F)
        if 0x58 <= b0 <= 0x5F:
            reg = reg_names_64[b0 - 0x58]
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 1, "bytes": hex(b0)[2:], "mnemonic": "pop", "operands": reg,
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 1
            continue

        # 11. REX.B Push/Pop r8..r15 (0x41 0x50..0x5F)
        if b0 == 0x41 and idx + 1 < limit:
            b1 = raw[idx + 1]
            if 0x50 <= b1 <= 0x57:
                reg = ext_regs_64[b1 - 0x50]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 2, "bytes": f"41 {hex(b1)[2:]}", "mnemonic": "push", "operands": reg,
                    "target_rva": None, "target_rva_hex": None,
                })
                idx += 2
                continue
            if 0x58 <= b1 <= 0x5F:
                reg = ext_regs_64[b1 - 0x58]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 2, "bytes": f"41 {hex(b1)[2:]}", "mnemonic": "pop", "operands": reg,
                    "target_rva": None, "target_rva_hex": None,
                })
                idx += 2
                continue

        # 12. mov r10, rcx (0x4C 0x8B 0xD1)
        if b0 == 0x4C and idx + 2 < limit and raw[idx + 1] == 0x8B and raw[idx + 2] == 0xD1:
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 3, "bytes": "4c 8b d1", "mnemonic": "mov", "operands": "r10, rcx",
                "target_rva": None, "target_rva_hex": None,
            })
            idx += 3
            continue

        # 13. mov [rsp+disp], r8..r15 (0x4C 0x89 ...)
        if b0 == 0x4C and idx + 3 < limit and raw[idx + 1] == 0x89:
            b2 = raw[idx + 2]
            b3 = raw[idx + 3]
            # disp8 with SIB 0x24: 4C 89 <0x44..0x7C> 24 <disp8>
            if (b2 & 0xC7) == 0x44 and b3 == 0x24 and idx + 4 < limit:
                reg_idx = (b2 >> 3) & 7
                disp = struct.unpack_from("<b", raw, idx + 4)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 5, "bytes": raw[idx:idx+5].hex(" "), "mnemonic": "mov",
                    "operands": f"qword ptr [rsp+{hex(disp)}], {ext_regs_64[reg_idx]}",
                    "target_rva": None, "target_rva_hex": None,
                })
                idx += 5
                continue
            # disp32 with SIB 0x24: 4C 89 <0x84..0xBC> 24 <disp32>
            if (b2 & 0xC7) == 0x84 and b3 == 0x24 and idx + 7 < limit:
                reg_idx = (b2 >> 3) & 7
                disp = struct.unpack_from("<i", raw, idx + 4)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 8, "bytes": raw[idx:idx+8].hex(" "), "mnemonic": "mov",
                    "operands": f"qword ptr [rsp+{hex(disp)}], {ext_regs_64[reg_idx]}",
                    "target_rva": None, "target_rva_hex": None,
                })
                idx += 8
                continue

        # 14. mov eax, imm32 (0xB8 <imm32>)
        if b0 == 0xB8 and idx + 4 < limit:
            imm = struct.unpack_from("<I", raw, idx + 1)[0]
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 5, "bytes": raw[idx:idx+5].hex(" "), "mnemonic": "mov",
                "operands": f"eax, {hex(imm)}", "target_rva": None, "target_rva_hex": None,
            })
            idx += 5
            continue

        # 15. REX.W sub rsp / add rsp / mov [rsp+disp], reg / mov rbp, rsp
        if b0 == 0x48 and idx + 2 < limit:
            b1 = raw[idx + 1]
            b2 = raw[idx + 2]

            # sub rsp, imm8 (48 83 ec <imm8>)
            if b1 == 0x83 and b2 == 0xEC and idx + 3 < limit:
                imm = struct.unpack_from("<B", raw, idx + 3)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 4, "bytes": raw[idx:idx+4].hex(" "), "mnemonic": "sub",
                    "operands": f"rsp, {hex(imm)}", "target_rva": None, "target_rva_hex": None,
                })
                idx += 4
                continue

            # sub rsp, imm32 (48 81 ec <imm32>)
            if b1 == 0x81 and b2 == 0xEC and idx + 6 < limit:
                imm = struct.unpack_from("<I", raw, idx + 3)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 7, "bytes": raw[idx:idx+7].hex(" "), "mnemonic": "sub",
                    "operands": f"rsp, {hex(imm)}", "target_rva": None, "target_rva_hex": None,
                })
                idx += 7
                continue

            # add rsp, imm8 (48 83 c4 <imm8>)
            if b1 == 0x83 and b2 == 0xC4 and idx + 3 < limit:
                imm = struct.unpack_from("<B", raw, idx + 3)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 4, "bytes": raw[idx:idx+4].hex(" "), "mnemonic": "add",
                    "operands": f"rsp, {hex(imm)}", "target_rva": None, "target_rva_hex": None,
                })
                idx += 4
                continue

            # add rsp, imm32 (48 81 c4 <imm32>)
            if b1 == 0x81 and b2 == 0xC4 and idx + 6 < limit:
                imm = struct.unpack_from("<I", raw, idx + 3)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 7, "bytes": raw[idx:idx+7].hex(" "), "mnemonic": "add",
                    "operands": f"rsp, {hex(imm)}", "target_rva": None, "target_rva_hex": None,
                })
                idx += 7
                continue

            # mov rbp, rsp (48 89 e5)
            if b1 == 0x89 and b2 == 0xE5:
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 3, "bytes": "48 89 e5", "mnemonic": "mov",
                    "operands": "rbp, rsp", "target_rva": None, "target_rva_hex": None,
                })
                idx += 3
                continue

            # mov rsp, rbp (48 89 ec)
            if b1 == 0x89 and b2 == 0xEC:
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 3, "bytes": "48 89 ec", "mnemonic": "mov",
                    "operands": "rsp, rbp", "target_rva": None, "target_rva_hex": None,
                })
                idx += 3
                continue

            # mov [rsp+disp8], reg (48 89 <modrm:0x44..0x7c> 24 <disp8>)
            if b1 == 0x89 and idx + 4 < limit and (b2 & 0xC7) == 0x44 and raw[idx + 3] == 0x24:
                reg_idx = (b2 >> 3) & 7
                disp = struct.unpack_from("<b", raw, idx + 4)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 5, "bytes": raw[idx:idx+5].hex(" "), "mnemonic": "mov",
                    "operands": f"qword ptr [rsp+{hex(disp)}], {reg_names_64[reg_idx]}",
                    "target_rva": None, "target_rva_hex": None,
                })
                idx += 5
                continue

            # mov [rsp+disp32], reg (48 89 <modrm:0x84..0xbc> 24 <disp32>)
            if b1 == 0x89 and idx + 7 < limit and (b2 & 0xC7) == 0x84 and raw[idx + 3] == 0x24:
                reg_idx = (b2 >> 3) & 7
                disp = struct.unpack_from("<i", raw, idx + 4)[0]
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 8, "bytes": raw[idx:idx+8].hex(" "), "mnemonic": "mov",
                    "operands": f"qword ptr [rsp+{hex(disp)}], {reg_names_64[reg_idx]}",
                    "target_rva": None, "target_rva_hex": None,
                })
                idx += 8
                continue

            # xor rax, rax (48 31 c0 / 48 33 c0)
            if (b1 == 0x31 or b1 == 0x33) and b2 == 0xC0:
                instructions.append({
                    "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                    "length": 3, "bytes": raw[idx:idx+3].hex(" "), "mnemonic": "xor",
                    "operands": "rax, rax", "target_rva": None, "target_rva_hex": None,
                })
                idx += 3
                continue

        # 16. xor eax, eax (31 C0 / 33 C0)
        if (b0 == 0x31 or b0 == 0x33) and idx + 1 < limit and raw[idx + 1] == 0xC0:
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 2, "bytes": raw[idx:idx+2].hex(" "), "mnemonic": "xor",
                "operands": "eax, eax", "target_rva": None, "target_rva_hex": None,
            })
            idx += 2
            continue

        # 17. RIP-relative call / jmp (FF 15 / FF 25)
        if b0 == 0xFF and idx + 5 < limit and (raw[idx + 1] == 0x15 or raw[idx + 1] == 0x25):
            is_call = raw[idx + 1] == 0x15
            disp = struct.unpack_from("<i", raw, idx + 2)[0]
            target_rva = curr_rva + 6 + disp
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 6, "bytes": raw[idx:idx+6].hex(" "),
                "mnemonic": "call" if is_call else "jmp",
                "operands": f"qword ptr [rip + {hex(disp)}]",
                "target_rva": target_rva, "target_rva_hex": hex(target_rva),
            })
            idx += 6
            continue

        # 18. Conditional branches rel32 (0F 84 / 0F 85)
        if b0 == 0x0F and idx + 5 < limit and (raw[idx + 1] == 0x84 or raw[idx + 1] == 0x85):
            is_jz = raw[idx + 1] == 0x84
            disp = struct.unpack_from("<i", raw, idx + 2)[0]
            target_rva = curr_rva + 6 + disp
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 6, "bytes": raw[idx:idx+6].hex(" "),
                "mnemonic": "jz" if is_jz else "jnz",
                "operands": hex(target_rva), "target_rva": target_rva, "target_rva_hex": hex(target_rva),
            })
            idx += 6
            continue

        # 19. Relative call rel32 (E8 <disp32>)
        if b0 == 0xE8 and idx + 4 < limit:
            disp = struct.unpack_from("<i", raw, idx + 1)[0]
            target_rva = curr_rva + 5 + disp
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 5, "bytes": raw[idx:idx+5].hex(" "), "mnemonic": "call",
                "operands": hex(target_rva), "target_rva": target_rva, "target_rva_hex": hex(target_rva),
            })
            idx += 5
            continue

        # 20. Relative jmp rel32 (E9 <disp32>)
        if b0 == 0xE9 and idx + 4 < limit:
            disp = struct.unpack_from("<i", raw, idx + 1)[0]
            target_rva = curr_rva + 5 + disp
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 5, "bytes": raw[idx:idx+5].hex(" "), "mnemonic": "jmp",
                "operands": hex(target_rva), "target_rva": target_rva, "target_rva_hex": hex(target_rva),
            })
            idx += 5
            continue

        # 21. Short jmp rel8 (EB <disp8>)
        if b0 == 0xEB and idx + 1 < limit:
            disp = struct.unpack_from("<b", raw, idx + 1)[0]
            target_rva = curr_rva + 2 + disp
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 2, "bytes": raw[idx:idx+2].hex(" "), "mnemonic": "jmp",
                "operands": f"short {hex(target_rva)}", "target_rva": target_rva, "target_rva_hex": hex(target_rva),
            })
            idx += 2
            continue

        # 22. Conditional short jumps (74 jz / 75 jnz <disp8>)
        if (b0 == 0x74 or b0 == 0x75) and idx + 1 < limit:
            disp = struct.unpack_from("<b", raw, idx + 1)[0]
            target_rva = curr_rva + 2 + disp
            instructions.append({
                "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
                "length": 2, "bytes": raw[idx:idx+2].hex(" "),
                "mnemonic": "jz" if b0 == 0x74 else "jnz",
                "operands": hex(target_rva), "target_rva": target_rva, "target_rva_hex": hex(target_rva),
            })
            idx += 2
            continue

        # 23. Resilient Fallback (single unrecognized byte)
        instructions.append({
            "offset": idx, "rva": curr_rva, "rva_hex": hex(curr_rva),
            "length": 1, "bytes": hex(b0)[2:].zfill(2), "mnemonic": "db",
            "operands": hex(b0), "target_rva": None, "target_rva_hex": None,
        })
        idx += 1

    return instructions


def detect_syscall_stubs(
    data: bytes,
    parsed_pe: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Scan executable sections and exported Nt*/Zw* functions to detect:
    - Standard / Hell's Gate direct syscall stubs (extracting SSN, RVA, symbol).
    - Hooked / Halo's Gate / Tartarus' Gate stubs (E9 inline jump at byte 0 or 3).
    - Standalone 0F 05 C3 (syscall; ret) indirect invocation gadgets.
    """
    empty_result: dict[str, Any] = {
        "stubs_detected": 0,
        "direct_stubs": [],
        "hooked_stubs": [],
        "indirect_gadgets": [],
        "has_direct_syscalls": False,
        "has_hooked_syscalls": False,
        "has_indirect_gadgets": False,
        "summary": "No valid PE data provided",
    }
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16:
        return empty_result

    raw = bytes(data)
    if parsed_pe is None:
        try:
            parsed_pe = parse_pe64_binary(raw)
        except Exception:
            parsed_pe = None

    sections = parsed_pe.get("sections", []) if parsed_pe else []

    def rva_to_offset(rva: int) -> Optional[int]:
        for sec in sections:
            va = sec.get("virtual_address", 0)
            span = max(sec.get("virtual_size", 0), sec.get("raw_size", 0))
            if va <= rva < va + span:
                raw_ptr = sec.get("raw_ptr", sec.get("raw_offset", 0))
                return raw_ptr + (rva - va)
        return None

    direct_stubs: list[dict[str, Any]] = []
    hooked_stubs: list[dict[str, Any]] = []
    indirect_gadgets: list[dict[str, Any]] = []
    recorded_rvas: set[int] = set()

    # 1. Export Directory Inspection (e.g. ntdll.dll Nt* / Zw* exports)
    if parsed_pe:
        exports_list = parsed_pe.get("exports", {}).get("exports", [])
        for exp in exports_list:
            fn_name = exp.get("name", "")
            rva_val = exp.get("rva", 0)
            exp_rva = int(rva_val, 16) if isinstance(rva_val, str) else int(rva_val)
            if not fn_name.startswith(("Nt", "Zw", "Sample", "stub")) or not exp_rva:
                continue

            off = rva_to_offset(exp_rva)
            if off is None or off + 8 > len(raw):
                continue

            stub_bytes = raw[off : min(len(raw), off + 32)]

            # Check Hook at byte 0: E9 <disp32>
            if stub_bytes[0] == 0xE9 and len(stub_bytes) >= 5:
                disp = struct.unpack_from("<i", stub_bytes, 1)[0]
                target_rva = exp_rva + 5 + disp
                hooked_stubs.append({
                    "symbol": fn_name,
                    "rva": hex(exp_rva),
                    "rva_int": exp_rva,
                    "stub_type": "hooked_byte0",
                    "hook_offset": 0,
                    "hooked": True,
                    "target_rva": hex(target_rva),
                    "bytes": stub_bytes[:16].hex(" "),
                })
                recorded_rvas.add(exp_rva)
                continue

            # Check Hook at byte 3: 4C 8B D1 E9 <disp32>
            if len(stub_bytes) >= 8 and stub_bytes[:3] == b"\x4c\x8b\xd1" and stub_bytes[3] == 0xE9:
                disp = struct.unpack_from("<i", stub_bytes, 4)[0]
                target_rva = exp_rva + 8 + disp
                hooked_stubs.append({
                    "symbol": fn_name,
                    "rva": hex(exp_rva),
                    "rva_int": exp_rva,
                    "stub_type": "hooked_byte3",
                    "hook_offset": 3,
                    "hooked": True,
                    "target_rva": hex(target_rva),
                    "bytes": stub_bytes[:16].hex(" "),
                })
                recorded_rvas.add(exp_rva)
                continue

            # Standard syscall stub: 4C 8B D1 B8 <ssn:u32>
            if len(stub_bytes) >= 8 and stub_bytes[:3] == b"\x4c\x8b\xd1" and stub_bytes[3] == 0xB8:
                ssn = struct.unpack_from("<I", stub_bytes, 4)[0]
                direct_stubs.append({
                    "symbol": fn_name,
                    "rva": hex(exp_rva),
                    "rva_int": exp_rva,
                    "ssn": ssn,
                    "ssn_hex": f"0x{ssn:04x}",
                    "stub_type": "standard_syscall",
                    "hooked": False,
                    "bytes": stub_bytes[:16].hex(" "),
                })
                recorded_rvas.add(exp_rva)
                continue

    # 2. Executable Sections Scan (or fallback raw scan if not parsed)
    exec_sections = []
    for sec in sections:
        raw_chars = sec.get("characteristics", "0x0")
        chars_val = int(raw_chars, 16) if isinstance(raw_chars, str) else int(raw_chars)
        if chars_val & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            exec_sections.append(sec)

    scan_targets = []
    if exec_sections:
        for sec in exec_sections:
            ptr = sec.get("raw_ptr", sec.get("raw_offset", 0))
            sz = sec.get("raw_size", 0)
            va = sec.get("virtual_address", 0)
            if ptr + sz > len(raw):
                sz = max(0, len(raw) - ptr)
            scan_targets.append((sec.get("name", ".text"), ptr, sz, va))
    else:
        scan_targets.append((".text", 0, len(raw), 0x1000))

    for sec_name, sec_ptr, sec_sz, sec_va in scan_targets:
        sec_slice = raw[sec_ptr : sec_ptr + sec_sz]

        # Scan for direct Hell's Gate stubs: 4C 8B D1 B8 <ssn:u32>
        pattern_direct = b"\x4c\x8b\xd1\xb8"
        start = 0
        while True:
            fpos = sec_slice.find(pattern_direct, start)
            if fpos == -1 or fpos + 8 > len(sec_slice):
                break
            stub_rva = sec_va + fpos
            if stub_rva not in recorded_rvas:
                ssn = struct.unpack_from("<I", sec_slice, fpos + 4)[0]
                stub_chunk = sec_slice[fpos : min(len(sec_slice), fpos + 24)]
                direct_stubs.append({
                    "symbol": f"stub_{hex(stub_rva)}",
                    "rva": hex(stub_rva),
                    "rva_int": stub_rva,
                    "ssn": ssn,
                    "ssn_hex": f"0x{ssn:04x}",
                    "stub_type": "standard_syscall",
                    "hooked": False,
                    "bytes": stub_chunk[:16].hex(" "),
                })
                recorded_rvas.add(stub_rva)
            start = fpos + 1

        # Scan for hooked stubs at byte 3 in section: 4C 8B D1 E9 <disp32>
        pattern_hook3 = b"\x4c\x8b\xd1\xe9"
        start = 0
        while True:
            fpos = sec_slice.find(pattern_hook3, start)
            if fpos == -1 or fpos + 8 > len(sec_slice):
                break
            stub_rva = sec_va + fpos
            if stub_rva not in recorded_rvas:
                disp = struct.unpack_from("<i", sec_slice, fpos + 4)[0]
                target_rva = stub_rva + 8 + disp
                stub_chunk = sec_slice[fpos : min(len(sec_slice), fpos + 24)]
                hooked_stubs.append({
                    "symbol": f"stub_{hex(stub_rva)}",
                    "rva": hex(stub_rva),
                    "rva_int": stub_rva,
                    "stub_type": "hooked_byte3",
                    "hook_offset": 3,
                    "hooked": True,
                    "target_rva": hex(target_rva),
                    "bytes": stub_chunk[:16].hex(" "),
                })
                recorded_rvas.add(stub_rva)
            start = fpos + 1

        # Scan for standalone 0F 05 C3 indirect syscall gadgets
        gadget_pat = b"\x0f\x05\xc3"
        start = 0
        while True:
            fpos = sec_slice.find(gadget_pat, start)
            if fpos == -1:
                break
            g_rva = sec_va + fpos
            indirect_gadgets.append({
                "rva": hex(g_rva),
                "rva_int": g_rva,
                "section": sec_name,
                "bytes": "0f 05 c3",
            })
            start = fpos + 1

    has_direct = len(direct_stubs) > 0
    has_hooked = len(hooked_stubs) > 0
    has_indirect = len(indirect_gadgets) > 0
    total_stubs = len(direct_stubs) + len(hooked_stubs)

    summary = (
        f"Detected {len(direct_stubs)} direct stubs, "
        f"{len(hooked_stubs)} hooked stubs, "
        f"{len(indirect_gadgets)} indirect gadgets"
    )

    return {
        "stubs_detected": total_stubs,
        "direct_stubs": direct_stubs,
        "hooked_stubs": hooked_stubs,
        "indirect_gadgets": indirect_gadgets,
        "has_direct_syscalls": has_direct,
        "has_hooked_syscalls": has_hooked,
        "has_indirect_gadgets": has_indirect,
        "summary": summary,
    }


def build_iat_eat_xref_graph(
    data: bytes,
    parsed_pe: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Walk executable sections for RIP-relative (FF 15/FF 25) and relative (E8/E9) transfers,
    correlate targets with IAT imported functions and EAT exported symbols,
    and output a structured dependency graph.
    """
    empty_result: dict[str, Any] = {
        "nodes": [],
        "edges": [],
        "iat_xref_count": 0,
        "eat_export_count": 0,
        "total_xrefs": 0,
    }
    if not isinstance(data, (bytes, bytearray)) or len(data) < 0x100:
        return empty_result

    raw = bytes(data)
    if parsed_pe is None:
        try:
            parsed_pe = parse_pe64_binary(raw)
        except Exception:
            return empty_result

    sections = parsed_pe.get("sections", [])

    def rva_to_offset(rva: int) -> Optional[int]:
        for sec in sections:
            va = sec.get("virtual_address", 0)
            span = max(sec.get("virtual_size", 0), sec.get("raw_size", 0))
            if va <= rva < va + span:
                raw_ptr = sec.get("raw_ptr", sec.get("raw_offset", 0))
                return raw_ptr + (rva - va)
        return None

    # 1. Resolve EAT symbols
    eat_map: dict[int, str] = {}
    for exp in parsed_pe.get("exports", {}).get("exports", []):
        fn_name = exp.get("name", "")
        rva_val = exp.get("rva", 0)
        rva_int = int(rva_val, 16) if isinstance(rva_val, str) else int(rva_val)
        if fn_name and rva_int:
            eat_map[rva_int] = fn_name

    # 2. Resolve IAT symbols (from DataDirectory[1] Import Table)
    iat_map: dict[int, str] = {}
    try:
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        opt_offset = e_lfanew + 24
        if opt_offset + 128 <= len(raw):
            import_rva, import_size = struct.unpack_from("<II", raw, opt_offset + 120)
            if import_rva != 0 and import_size != 0:
                desc_off = rva_to_offset(import_rva)
                if desc_off is not None:
                    curr_desc = desc_off
                    while curr_desc + 20 <= len(raw):
                        orig_thunk_rva, _ts, _fwd, name_rva, first_thunk_rva = struct.unpack_from(
                            "<IIIII", raw, curr_desc
                        )
                        if orig_thunk_rva == 0 and name_rva == 0 and first_thunk_rva == 0:
                            break
                        curr_desc += 20
                        if first_thunk_rva == 0:
                            continue

                        dll_name = "UNKNOWN.dll"
                        name_off = rva_to_offset(name_rva)
                        if name_off is not None and name_off < len(raw):
                            dll_name = raw[name_off:].split(b"\x00", 1)[0].decode("ascii", errors="replace")

                        thunk_table_rva = orig_thunk_rva if orig_thunk_rva != 0 else first_thunk_rva
                        thunk_off = rva_to_offset(thunk_table_rva)
                        if thunk_off is None:
                            continue

                        thunk_idx = 0
                        while thunk_off + thunk_idx * 8 + 8 <= len(raw) and thunk_idx < 4096:
                            thunk_val = struct.unpack_from("<Q", raw, thunk_off + thunk_idx * 8)[0]
                            if thunk_val == 0:
                                break
                            slot_rva = first_thunk_rva + thunk_idx * 8
                            if thunk_val & 0x8000000000000000:
                                ord_num = thunk_val & 0xFFFF
                                sym_name = f"{dll_name}!#{ord_num}"
                            else:
                                ibn_rva = thunk_val & 0x7FFFFFFF
                                ibn_off = rva_to_offset(ibn_rva)
                                if ibn_off is not None and ibn_off + 2 < len(raw):
                                    fn_name = raw[ibn_off + 2:].split(b"\x00", 1)[0].decode("ascii", errors="replace")
                                    sym_name = f"{dll_name}!{fn_name}"
                                else:
                                    sym_name = f"{dll_name}!func_{hex(ibn_rva)}"
                            iat_map[slot_rva] = sym_name
                            thunk_idx += 1
    except Exception:
        pass

    nodes_dict: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    iat_xref_count = 0
    eat_export_count = 0

    ep_rva = parsed_pe.get("entry_point_rva", 0)
    if ep_rva:
        nodes_dict[f"CODE:{hex(ep_rva)}"] = {
            "id": f"CODE:{hex(ep_rva)}",
            "label": "entry_point",
            "type": "entry",
            "rva": hex(ep_rva),
        }

    # 3. Walk Executable Sections for Call/Jump Targets
    for sec in sections:
        raw_chars = sec.get("characteristics", "0x0")
        chars_val = int(raw_chars, 16) if isinstance(raw_chars, str) else int(raw_chars)
        if not (chars_val & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue

        sec_ptr = sec.get("raw_ptr", sec.get("raw_offset", 0))
        sec_sz = sec.get("raw_size", 0)
        sec_va = sec.get("virtual_address", 0)
        if sec_ptr + sec_sz > len(raw):
            sec_sz = max(0, len(raw) - sec_ptr)
        sec_bytes = raw[sec_ptr : sec_ptr + sec_sz]

        i = 0
        limit = len(sec_bytes)
        while i < limit - 4 and len(edges) < 10000:
            curr_insn_rva = sec_va + i
            b0 = sec_bytes[i]

            # RIP-relative call/jmp: FF 15 disp32 / FF 25 disp32 (6 bytes)
            if b0 == 0xFF and i + 6 <= limit and (sec_bytes[i+1] == 0x15 or sec_bytes[i+1] == 0x25):
                is_call = sec_bytes[i+1] == 0x15
                opcode = "FF15" if is_call else "FF25"
                call_type = "call_rip_relative" if is_call else "jmp_rip_relative"
                disp = struct.unpack_from("<i", sec_bytes, i + 2)[0]
                target_rva = curr_insn_rva + 6 + disp

                if target_rva in iat_map:
                    sym = iat_map[target_rva]
                    target_id = f"IAT:{sym}"
                    iat_xref_count += 1
                    if target_id not in nodes_dict:
                        nodes_dict[target_id] = {
                            "id": target_id,
                            "label": sym.split("!", 1)[-1],
                            "type": "import",
                            "rva": hex(target_rva),
                        }
                    edges.append({
                        "source": hex(curr_insn_rva),
                        "target": target_id,
                        "call_type": call_type,
                        "opcode": opcode,
                        "source_rva": hex(curr_insn_rva),
                        "target_rva": hex(target_rva),
                        "symbol": sym.split("!", 1)[-1],
                    })
                elif target_rva in eat_map:
                    sym = eat_map[target_rva]
                    target_id = f"EAT:{sym}"
                    eat_export_count += 1
                    if target_id not in nodes_dict:
                        nodes_dict[target_id] = {
                            "id": target_id,
                            "label": sym,
                            "type": "export",
                            "rva": hex(target_rva),
                        }
                    edges.append({
                        "source": hex(curr_insn_rva),
                        "target": target_id,
                        "call_type": call_type,
                        "opcode": opcode,
                        "source_rva": hex(curr_insn_rva),
                        "target_rva": hex(target_rva),
                        "symbol": sym,
                    })
                i += 6
                continue

            # Relative call/jmp: E8 disp32 / E9 disp32 (5 bytes)
            if (b0 == 0xE8 or b0 == 0xE9) and i + 5 <= limit:
                is_call = b0 == 0xE8
                opcode = "E8" if is_call else "E9"
                call_type = "call_relative" if is_call else "jmp_relative"
                disp = struct.unpack_from("<i", sec_bytes, i + 1)[0]
                target_rva = curr_insn_rva + 5 + disp

                if target_rva in eat_map:
                    sym = eat_map[target_rva]
                    target_id = f"EAT:{sym}"
                    eat_export_count += 1
                    if target_id not in nodes_dict:
                        nodes_dict[target_id] = {
                            "id": target_id,
                            "label": sym,
                            "type": "export",
                            "rva": hex(target_rva),
                        }
                    edges.append({
                        "source": hex(curr_insn_rva),
                        "target": target_id,
                        "call_type": call_type,
                        "opcode": opcode,
                        "source_rva": hex(curr_insn_rva),
                        "target_rva": hex(target_rva),
                        "symbol": sym,
                    })
                elif target_rva in iat_map:
                    sym = iat_map[target_rva]
                    target_id = f"IAT:{sym}"
                    iat_xref_count += 1
                    if target_id not in nodes_dict:
                        nodes_dict[target_id] = {
                            "id": target_id,
                            "label": sym.split("!", 1)[-1],
                            "type": "import",
                            "rva": hex(target_rva),
                        }
                    edges.append({
                        "source": hex(curr_insn_rva),
                        "target": target_id,
                        "call_type": call_type,
                        "opcode": opcode,
                        "source_rva": hex(curr_insn_rva),
                        "target_rva": hex(target_rva),
                        "symbol": sym.split("!", 1)[-1],
                    })
                i += 5
                continue

            i += 1

    for edge in edges:
        src_id = f"CODE:{edge['source_rva']}"
        if src_id not in nodes_dict:
            nodes_dict[src_id] = {
                "id": src_id,
                "label": f"sub_{edge['source_rva'][2:]}",
                "type": "code",
                "rva": edge["source_rva"],
            }

    return {
        "nodes": list(nodes_dict.values()),
        "edges": edges,
        "iat_xref_count": iat_xref_count,
        "eat_export_count": eat_export_count,
        "total_xrefs": len(edges),
    }
