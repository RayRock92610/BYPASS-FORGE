import pytest
from scripts.triage_event import extract_metadata, sanitize_input

def test_sanitize_input():
    assert sanitize_input("hello;world") == "helloworld"
    assert sanitize_input("cat /etc/passwd | grep root") == "cat /etc/passwd  grep root"
    assert sanitize_input("valid-branch-name-123") == "valid-branch-name-123"

def test_extract_metadata():
    body = "Found a header injection vulnerability"
    metadata = extract_metadata(body)
    assert metadata["header_injection"] == True
    assert metadata["path_traversal"] == False

def test_sanitize_input_empty():
    assert sanitize_input(None) == ""
    assert sanitize_input(123) == ""
