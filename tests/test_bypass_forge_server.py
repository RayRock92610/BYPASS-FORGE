from bypass_forge_server import classify


def test_classify():
    # BYPASS
    assert classify(200) == "BYPASS"

    # REDIRECT
    assert classify(301) == "REDIRECT"
    assert classify(302) == "REDIRECT"
    assert classify(307) == "REDIRECT"
    assert classify(308) == "REDIRECT"

    # AUTH
    assert classify(401) == "AUTH"

    # BLOCKED
    assert classify(403) == "BLOCKED"

    # NOT_FOUND
    assert classify(404) == "NOT_FOUND"

    # SERVER_ERR
    assert classify(500) == "SERVER_ERR"

    # OTHER
    assert classify(201) == "OTHER"
    assert classify(400) == "OTHER"
    assert classify(503) == "OTHER"
    assert classify("invalid") == "OTHER"
    assert classify(None) == "OTHER"
