# Jules Agent Boundary Contract

This document outlines the architectural boundaries and operational rules for automated agents (e.g., Jules) interacting with the BYPASS-FORGE repository.

## 1. Strict Shell Argument Sanitization
- All shell arguments MUST be strictly sanitized.
- When invoking commands via `subprocess` (in Python) or external calls like `curl`, do NOT use unquoted variable expansions.
- Enforce `shell=False` across all Python `subprocess` invocations.
- Mandate `shlex.split()` tokenization for any command arguments.

## 2. Directory Modification Restrictions
- Agents are permitted to modify modular test generators exclusively within the following directories:
  - `bypass_forge/`
  - `tests/`
  - Workflow definitions (e.g., `.github/workflows/`)
- Modifications to core framework files or execution environments outside these directories must be explicitly authorized by a human operator unless performing CI/CD configuration tasks.

## 3. Credential & Leak Prevention
- Explicitly prohibit printing or persisting raw authorization tokens, external target URLs, or full stack traces (`str(e)` / `exc_info=True`) in logs or triage artifacts.
- All error messages must be sanitized and free of sensitive environment context.

## 4. Network Probing Restrictions
- Do NOT modify or introduce external network probing logic without writing corresponding isolated mock unit tests.
- All test fixtures for bypass techniques must rely exclusively on mocked HTTP responses (e.g., `unittest.mock` or `pytest-mock`).
- Headless GitHub Actions runners must be able to execute the test suite completely offline (no actual network requests to external targets).
