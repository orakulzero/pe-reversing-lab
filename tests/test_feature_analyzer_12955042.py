"""
tests/test_validator_pe_analysis_input.py
Test suite for validate_pe_analysis_input helper function.
"""
import pytest
from pathlib import Path
from pe_reversing_lab.analyzer import validate_pe_analysis_input


def test_validate_pe_analysis_input_accepts_valid_bytes():
    """
    Verify that validate_pe_analysis_input accepts valid bytes input
    and returns normalized dict with correct types.
    """
    raw = b"MZ\x90\x00" + b"\x00" * 60
    result = validate_pe_analysis_input(raw, max_instructions=100, base_rva=0x1000)
    
    assert result["valid"] is True
    assert result["input_type"] == "bytes"
    assert result["size"] == len(raw)
    assert result["max_instructions"] == 100
    assert result["base_rva"] == 0x1000
    assert "errors" not in result


def test_validate_pe_analysis_input_rejects_invalid_types():
    """
    Verify that validate_pe_analysis_input rejects unsupported input types
    and returns error details.
    """
    result = validate_pe_analysis_input(12345, max_instructions=100, base_rva=0x1000)
    
    assert result["valid"] is False
    assert result["input_type"] == "invalid"
    assert "errors" in result
    assert "Unsupported input type" in result["errors"][0]


def test_validate_pe_analysis_input_validates_parameter_ranges():
    """
    Verify that validate_pe_analysis_input enforces parameter constraints
    for max_instructions and base_rva.
    """
    raw = b"MZ\x90\x00"
    result = validate_pe_analysis_input(raw, max_instructions=-10, base_rva=-5000)
    
    assert result["valid"] is False
    assert "errors" in result
    assert any("max_instructions" in err for err in result["errors"])
    assert any("base_rva" in err for err in result["errors"])
    assert result["max_instructions"] == -10
    assert result["base_rva"] == -5000
