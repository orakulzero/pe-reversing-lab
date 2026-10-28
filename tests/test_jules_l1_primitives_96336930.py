import pytest
import struct
from pe_reversing_lab.l1_primitives import parse_rich_header

def test_parse_rich_header_rich_no_dans():
    """
    Test the `parse_rich_header` function with an edge case where the `data` 
    contains the `b'Rich'` marker but no corresponding `b'DanS'` marker, 
    ensuring it returns the expected empty result without raising exceptions.
    """
    # e_lfanew points to 0x80
    data = bytearray(0x80)
    struct.pack_into("<I", data, 0x3C, 0x80)
    
    # Place "Rich" at 0x60, so that the search for DanS executes loop iterations 
    # but does not find it.
    rich_offset = 0x60
    xor_key = 0xDEADBEEF
    data[rich_offset:rich_offset+4] = b"Rich"
    struct.pack_into("<I", data, rich_offset+4, xor_key)
    
    # Fill the prior space with dummy data so the DanS search loop runs
    # but finds nothing matching DanS ^ xor_key
    for i in range(0x60 - 4, 0x3C, -4):
        struct.pack_into("<I", data, i, 0)
        
    result = parse_rich_header(data, 0x80)
    
    assert result["present"] is False
    assert result["xor_key"] == hex(xor_key)
    assert result["dans_offset"] == 0
    assert result["rich_offset"] == rich_offset
    assert result["record_count"] == 0
    assert result["records"] == []
    assert result["rich_hash"] == ""
