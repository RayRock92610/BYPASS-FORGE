from unittest.mock import MagicMock, patch
import urllib.error

from bypass_forge_server import classify, findings, fire_technique


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


@patch('bypass_forge_server.urllib.request.urlopen')
def test_fire_technique_success(mock_urlopen):
    findings.clear()
    mock_res = MagicMock()
    mock_res.status = 200
    mock_res.read.return_value = b"OK"
    mock_urlopen.return_value = mock_res

    tech = {
        "id": "t1", "cat": "url", "label": "test",
        "mod": "url", "val": "{url}?test=1"
    }
    result = fire_technique("http://example.com/path", tech)

    assert result["code"] == 200
    assert result["bytes"] == 2
    assert result["verdict"] == "BYPASS"
    assert result["id"] == "t1"
    assert result["cat"] == "url"
    assert result["label"] == "test"
    assert result["url"] == "http://example.com/path?test=1"
    assert result["method"] == "GET"
    assert "ts" in result
    assert "sig" in result

    args, _kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.full_url == "http://example.com/path?test=1"
    assert req.method == "GET"

@patch('bypass_forge_server.urllib.request.urlopen')
def test_fire_technique_header(mock_urlopen):
    findings.clear()
    mock_res = MagicMock()
    mock_res.status = 403
    mock_res.read.return_value = b""
    mock_urlopen.return_value = mock_res

    tech = {
        "id": "t2", "cat": "header", "label": "test header",
        "mod": "header", "val": "X-Forwarded-For: 127.0.0.1"
    }
    result = fire_technique("http://example.com/path", tech)

    assert result["code"] == 403
    assert result["verdict"] == "BLOCKED"
    assert result["method"] == "GET"

    args, _kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.get_header("X-forwarded-for") == "127.0.0.1"

@patch('bypass_forge_server.urllib.request.urlopen')
def test_fire_technique_verb(mock_urlopen):
    findings.clear()
    mock_res = MagicMock()
    mock_res.status = 404
    mock_res.read.return_value = b"Not Found"
    mock_urlopen.return_value = mock_res

    tech = {
        "id": "t3", "cat": "verb", "label": "test verb",
        "mod": "verb", "val": "POST"
    }
    result = fire_technique("http://example.com/path", tech)

    assert result["code"] == 404
    assert result["verdict"] == "NOT_FOUND"
    assert result["method"] == "POST"

    args, _kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.method == "POST"

@patch('bypass_forge_server.urllib.request.urlopen')
def test_fire_technique_http_error(mock_urlopen):
    findings.clear()
    mock_error = urllib.error.HTTPError("http://example.com/path", 500, "Internal Server Error", {}, None)
    mock_urlopen.side_effect = mock_error

    tech = {
        "id": "t4", "cat": "url", "label": "test error",
        "mod": "url", "val": "{url}"
    }
    result = fire_technique("http://example.com/path", tech)

    assert result["code"] == 500
    assert result["bytes"] == 0
    assert result["verdict"] == "SERVER_ERR"

@patch('bypass_forge_server.urllib.request.urlopen')
def test_fire_technique_url_error(mock_urlopen):
    findings.clear()
    mock_error = urllib.error.URLError("Connection refused")
    mock_urlopen.side_effect = mock_error

    tech = {
        "id": "t5", "cat": "url", "label": "test url error",
        "mod": "url", "val": "{url}"
    }
    result = fire_technique("http://example.com/path", tech)

    assert result["code"] == 0
    assert result["bytes"] == 0
    assert result["verdict"] == "OTHER"
