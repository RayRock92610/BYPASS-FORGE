import json
import os
import sys
import re

def sanitize_input(text):
    if not isinstance(text, str):
        return ""
    # Remove potentially dangerous shell injection characters
    return re.sub(r'[;&|`$<>\\*?{}[\]!]', '', text)

def extract_metadata(body):
    metadata = {
        "header_injection": False,
        "path_traversal": False,
        "verb_tampering": False,
        "protocol_smuggling": False
    }
    body_lower = body.lower()
    if "header injection" in body_lower:
        metadata["header_injection"] = True
    if "path traversal" in body_lower:
        metadata["path_traversal"] = True
    if "verb tampering" in body_lower:
        metadata["verb_tampering"] = True
    if "protocol smuggling" in body_lower:
        metadata["protocol_smuggling"] = True
    return metadata

def main():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        diagnostic = {"error": "GITHUB_EVENT_PATH not set or file does not exist."}
        print(json.dumps(diagnostic))
        sys.exit(1)

    try:
        with open(event_path, "r") as f:
            event_data = json.load(f)
    except Exception as e:
        diagnostic = {"error": "Invalid JSON in GITHUB_EVENT_PATH."}
        print(json.dumps(diagnostic))
        sys.exit(1)

    # Determine if it's an issue or PR
    body = ""
    if "issue" in event_data and "body" in event_data["issue"]:
        body = event_data["issue"]["body"] or ""
    elif "pull_request" in event_data and "body" in event_data["pull_request"]:
        body = event_data["pull_request"]["body"] or ""
    else:
        diagnostic = {"error": "No issue or pull_request body found in event data."}
        print(json.dumps(diagnostic))
        sys.exit(1)

    sanitized_body = sanitize_input(body)
    metadata = extract_metadata(sanitized_body)

    context = {
        "sanitized_body": sanitized_body,
        "metadata": metadata
    }

    print(json.dumps(context))
    sys.exit(0)

if __name__ == "__main__":
    main()
