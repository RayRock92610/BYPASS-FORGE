from bypass_forge_server import MAX_URL_LEN, sanitize_url

def test_sanitize_url_empty_or_too_long():
    url, err = sanitize_url("")
    assert url is None
    assert err == "URL too long or empty"

    url, err = sanitize_url(None)
    assert url is None
    assert err == "URL too long or empty"

    long_url = "http://example.com/" + "a" * MAX_URL_LEN
    url, err = sanitize_url(long_url)
    assert url is None
    assert err == "URL too long or empty"

def test_sanitize_url_whitespace_stripping():
    # It must start with http/https but we check whitespace stripping
    url, err = sanitize_url("  http://example.com  ")
    assert url == "http://example.com"
    assert err is None

def test_sanitize_url_invalid_scheme():
    url, err = sanitize_url("ftp://example.com")
    assert url is None
    assert err == "Must start with http:// or https://"

    url, err = sanitize_url("http ://example.com")
    assert url is None
    assert err == "Must start with http:// or https://"

def test_sanitize_url_blocked_hosts():
    url, err = sanitize_url("http://localhost")
    assert url is None
    assert err == "Blocked host: localhost"

    url, err = sanitize_url("http://169.254.169.254/latest/meta-data/")
    assert url is None
    assert err == "Blocked host: 169.254.169.254"

    url, err = sanitize_url("http://0.0.0.0:8080/")
    assert url is None
    assert err == "Blocked host: 0.0.0.0"

def test_sanitize_url_private_ips():
    url, err = sanitize_url("http://10.0.0.1/admin")
    assert url is None
    assert err == "Private IP range blocked"

    url, err = sanitize_url("http://172.16.0.1/admin")
    assert url is None
    assert err == "Private IP range blocked"

    url, err = sanitize_url("http://172.31.255.255/admin")
    assert url is None
    assert err == "Private IP range blocked"

    url, err = sanitize_url("http://192.168.1.1/admin")
    assert url is None
    assert err == "Private IP range blocked"

def test_sanitize_url_control_chars():
    # \x00 is a control char.
    url, err = sanitize_url("http://example.com/\x00test")
    assert url == "http://example.com/test"
    assert err is None

def test_sanitize_url_valid():
    url, err = sanitize_url("https://example.com/path?q=1")
    assert url == "https://example.com/path?q=1"
    assert err is None
