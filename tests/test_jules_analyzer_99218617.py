import pytest
from pe_reversing_lab.analyzer import _disassemble_x64_instructions

def test_non_peb_walk_extended_register():
    """
    Test the edge case where a PE file contains an instruction with a REX prefix
    that modifies the extended register but does not follow the expected pattern
    for a PEB-walk shellcode.
    """
    # 0x65 = GS prefix
    # 0x4C = REX.WR
    # 0x8B = MOV
    # 0x25 (or another value), we need the raw[idx+1] check in analyzer.py
    # wait, the code is: if idx + 5 < limit and raw[idx + 1] == 0x25 and raw[idx + 2:idx + 6] == b"\x60\x00\x00\x00":
    # note that idx points to modrm. so raw[idx] is modrm, raw[idx+1] is SIB
    # analyzer requires raw[idx+1] == 0x25. 
    # 0x14 = ModRM (mod=0, reg=2, rm=4)
    # 0x25 = SIB
    # 0x10, 0x00, 0x00, 0x00 = disp32 = 0x10 (not 0x60)
    raw_bytes = b"\x65\x4c\x8b\x14\x25\x10\x00\x00\x00"
    instructions = _disassemble_x64_instructions(raw_bytes, base_rva=0x1000)
    
    # It should not flag as is_peb_walk
    assert len(instructions) > 0
    instr = instructions[0]
    assert instr.get("is_peb_walk", False) is False

def test_truncated_peb_walk_like_instruction():
    """
    Test boundary input where the instruction starts like a PEB walk but gets truncated.
    """
    # 0x65, 0x4c, 0x8b, 0x14, 0x25, 0x60 but missing the rest of displacement
    raw_bytes = b"\x65\x4c\x8b\x14\x25\x60"
    instructions = _disassemble_x64_instructions(raw_bytes, base_rva=0x1000)
    
    assert len(instructions) > 0
    instr = instructions[0]
    assert instr.get("is_peb_walk", False) is False

def test_genuine_peb_walk_instruction():
    """
    Test genuine PEB walk to ensure the positive case is still caught.
    """
    # mov r10, gs:[0x60]
    # REX = 0x4c, ModRM = 0x14 (r10), SIB = 0x25, Disp = 0x60000000
    raw_bytes = b"\x65\x4c\x8b\x14\x25\x60\x00\x00\x00"
    instructions = _disassemble_x64_instructions(raw_bytes, base_rva=0x1000)
    
    assert len(instructions) == 1
    instr = instructions[0]
    assert instr.get("is_peb_walk", False) is True
    assert instr["mnemonic"] == "mov"
    assert "gs:[0x60]" in instr["operands"]
    assert "r10" in instr["operands"]

def test_empty_input():
    """
    Test invariant check with empty bytes.
    """
    instructions = _disassemble_x64_instructions(b"", base_rva=0x1000)
    assert instructions == []

def test_just_prefixes():
    """
    Test invariant check with only prefixes and no opcode.
    """
    raw_bytes = b"\x65\x4c"
    instructions = _disassemble_x64_instructions(raw_bytes, base_rva=0x1000)
    assert len(instructions) == 1
    assert instructions[0]["mnemonic"] == "db"

def test_peb_walk_wrong_modrm():
    """
    Test a near-match for PEB walk but with a different SIB byte (not 0x25).
    """
    raw_bytes = b"\x65\x4c\x8b\x14\x26\x60\x00\x00\x00"
    instructions = _disassemble_x64_instructions(raw_bytes, base_rva=0x1000)
    assert len(instructions) > 0
    assert instructions[0].get("is_peb_walk", False) is False
