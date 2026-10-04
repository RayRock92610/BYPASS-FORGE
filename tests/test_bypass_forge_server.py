import io
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from bypass_forge_server import classify, fire_technique


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


class TestFireTechnique(unittest.TestCase):
    @patch("bypass_forge_server.urllib.request.urlopen")
    def test_fire_technique_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.read.return_value = b"OK"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = fire_technique(
            "http://127.0.0.1:8000",
            {
                "id": "1",
                "cat": "header",
                "label": "inject",
                "mod": "header",
                "val": "X-Custom: 1",
                "desc": "header_inject",
            },
        )
        self.assertIsNotNone(result)

    @patch("bypass_forge_server.urllib.request.urlopen")
    def test_fire_technique_http_error(self, mock_urlopen):
        # HTTPError requires url, code, msg, hdrs, fp
        fp = io.BytesIO(b"Access Denied")
        error = HTTPError("http://127.0.0.1:8000", 403, "Forbidden", hdrs={}, fp=fp)
        mock_urlopen.side_effect = error

        result = fire_technique(
            "http://127.0.0.1:8000",
            {
                "id": "2",
                "cat": "path",
                "label": "bypass",
                "mod": "url",
                "val": "UPPER",
                "desc": "path_bypass",
            },
        )
        self.assertIsNotNone(result)

    @patch("bypass_forge_server.urllib.request.urlopen")
    def test_fire_technique_url_error(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection refused")
        result = fire_technique(
            "http://127.0.0.1:8000",
            {
                "id": "3",
                "cat": "verb",
                "label": "tamper",
                "mod": "verb",
                "val": "POST",
                "desc": "verb_tamper",
            },
        )
        self.assertIsNotNone(result)
