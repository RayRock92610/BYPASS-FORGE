from bypass_forge_server import validate_techniques, BYPASS_TECHNIQUES

def test_validate_techniques_valid():
    # Take a few known valid IDs
    valid_ids = [BYPASS_TECHNIQUES[0]["id"], BYPASS_TECHNIQUES[1]["id"]]
    result = validate_techniques(valid_ids)
    assert result == valid_ids

def test_validate_techniques_invalid():
    invalid_ids = ["INVALID_1", "INVALID_2"]
    result = validate_techniques(invalid_ids)
    assert result == []

def test_validate_techniques_mixed():
    valid_id = BYPASS_TECHNIQUES[0]["id"]
    mixed_ids = ["INVALID_1", valid_id, "INVALID_2"]
    result = validate_techniques(mixed_ids)
    assert result == [valid_id]

def test_validate_techniques_empty():
    result = validate_techniques([])
    assert result == []

def test_validate_techniques_duplicates():
    valid_id = BYPASS_TECHNIQUES[0]["id"]
    ids = [valid_id, valid_id]
    result = validate_techniques(ids)
    assert result == [valid_id, valid_id]

def test_validate_techniques_all_valid():
    all_valid = [t["id"] for t in BYPASS_TECHNIQUES]
    result = validate_techniques(all_valid)
    assert result == all_valid
