import pytest
from pe_reversing_lab.analyzer import _disassemble_x64_instructions

def test_disassemble_unterminated_prefix_run():
    """
    Test _disassemble_x64_instructions with a byte sequence consisting solely of an 
    unterminated REX/segment prefix run truncated at the buffer boundary.
    """
    raw = b"\x65\x48"
    base_rva = 0x1000
    instructions = _disassemble_x64_instructions(raw, base_rva)
    
    assert len(instructions) == 1
    
    inst = instructions[0]
    assert inst["mnemonic"] == "db"
    assert inst["length"] == len(raw)
    assert inst["rva"] == base_rva
    assert inst["is_terminator"] is False
    assert inst["fallthrough_rva"] == base_rva + len(raw)
