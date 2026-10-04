from bypass_forge_server import classify


def test_classify():
    assert classify(200) == "BYPASS"
    assert classify(301) == "REDIRECT"
    assert classify(302) == "REDIRECT"
    assert classify(307) == "REDIRECT"
    assert classify(308) == "REDIRECT"
    assert classify(401) == "AUTH"
    assert classify(403) == "BLOCKED"
    assert classify(404) == "NOT_FOUND"
    assert classify(500) == "SERVER_ERR"

    # Test OTHER cases
    assert classify(0) == "OTHER"
    assert classify(201) == "OTHER"
    assert classify(400) == "OTHER"
    assert classify(502) == "OTHER"
    assert classify("invalid") == "OTHER"
    assert classify(None) == "OTHER"
