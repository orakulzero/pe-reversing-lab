import pytest
import struct
from pe_reversing_lab.analyzer import _disassemble_x64_instructions, _decode_modrm_length, _load_pe_bytes
from pathlib import Path

def test_disassemble_single_byte_prefix():
    """
    Test passing a single-byte prefix to _disassemble_x64_instructions and asserts that it returns exactly one instruction with 'mnemonic': 'db', 'length': 1, and 'bytes': '66'.
    """
    raw_data = b'\x66'
    base_rva = 0x1000
    
    instructions = _disassemble_x64_instructions(raw_data, base_rva)
    
    assert len(instructions) == 1
    
    instr = instructions[0]
    
    assert instr["mnemonic"] == "db"
    assert instr["length"] == 1
    assert instr["bytes"] == "66"
    assert instr["offset"] == 0
    assert instr["rva"] == 0x1000

def test_decode_modrm_length_out_of_bounds():
    assert _decode_modrm_length(b'\x00', 1, 1) == 0

def test_load_pe_bytes_invalid_path():
    assert _load_pe_bytes("invalid_path_that_does_not_exist") is None

def test_load_pe_bytes_from_bytes():
    assert _load_pe_bytes(b'test') == b'test'

def test_disassemble_x64_nop():
    instructions = _disassemble_x64_instructions(b'\x90', 0x1000)
    assert len(instructions) == 1
    assert instructions[0]["mnemonic"] == "nop"

def test_disassemble_x64_ret():
    instructions = _disassemble_x64_instructions(b'\xc3', 0x1000)
    assert len(instructions) == 1
    assert instructions[0]["mnemonic"] == "ret"

def test_disassemble_x64_int3():
    instructions = _disassemble_x64_instructions(b'\xcc', 0x1000)
    assert len(instructions) == 1
    assert instructions[0]["mnemonic"] == "int3"

def test_disassemble_x64_jmp_short():
    instructions = _disassemble_x64_instructions(b'\xeb\x05', 0x1000)
    assert len(instructions) == 1
    assert instructions[0]["mnemonic"] == "jmp"
    assert instructions[0]["target_rva"] == 0x1000 + 2 + 5

def test_disassemble_x64_call_relative():
    instructions = _disassemble_x64_instructions(b'\xe8\x05\x00\x00\x00', 0x1000)
    assert len(instructions) == 1
    assert instructions[0]["mnemonic"] == "call"
    assert instructions[0]["target_rva"] == 0x1000 + 5 + 5
