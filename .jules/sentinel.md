# Agent Execution Contract

This document outlines the architectural boundaries and operational rules for automated agents (e.g., Jules) interacting with the BYPASS-FORGE repository.

## 1. Strict Shell Argument Sanitization
- All shell arguments MUST be strictly sanitized.
- When invoking commands via `subprocess` (in Python) or external calls like `curl`, do NOT use unquoted variable expansions.
- Prefer using lists for arguments in `subprocess.run` (e.g., `subprocess.run(["ls", "-l", target_dir])`) rather than `shell=True` to prevent command injection vulnerabilities.

## 2. Directory Modification Restrictions
- Agents are permitted to modify modular test generators exclusively within the following directories:
  - `bypass_forge/`
  - `tests/`
- Modifications to core framework files or execution environments outside these directories must be explicitly authorized by a human operator unless performing CI/CD configuration tasks.

## 3. Network Probing Restrictions
- Do NOT modify or introduce external network probing logic without writing corresponding isolated mock unit tests.
- All test fixtures for bypass techniques must rely exclusively on mocked HTTP responses (e.g., `unittest.mock` or `pytest-mock`).
- Headless GitHub Actions runners must be able to execute the test suite completely offline (no actual network requests to external targets).
