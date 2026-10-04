import pytest
from bypass_forge_server import validate_techniques, BYPASS_TECHNIQUES

def test_validate_techniques_empty_list():
    assert validate_techniques([]) == []

def test_validate_techniques_all_valid():
    valid_id = BYPASS_TECHNIQUES[0]["id"]
    assert validate_techniques([valid_id]) == [valid_id]

def test_validate_techniques_all_invalid():
    assert validate_techniques(["INVALID1", "INVALID2"]) == []

def test_validate_techniques_mixed():
    valid_id = BYPASS_TECHNIQUES[0]["id"]
    assert validate_techniques(["INVALID1", valid_id, "INVALID2"]) == [valid_id]

def test_validate_techniques_duplicate_valid():
    valid_id = BYPASS_TECHNIQUES[0]["id"]
    # The current implementation uses list comprehension over the input list,
    # so duplicates in the input will be retained in the output.
    assert validate_techniques([valid_id, valid_id]) == [valid_id, valid_id]
