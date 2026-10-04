import pytest
from scripts.triage_event import extract_metadata, sanitize_input

def test_sanitize_input():
    assert sanitize_input("hello;world") == "helloworld"
    assert sanitize_input("cat /etc/passwd | grep root") == "cat /etc/passwd  grep root"

def test_extract_metadata():
    body = "Found a header injection vulnerability"
    metadata = extract_metadata(body)
    assert metadata["header_injection"] == True
    assert metadata["path_traversal"] == False
