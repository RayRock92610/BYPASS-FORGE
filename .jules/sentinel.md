# Jules Agent Boundary Contract

This file defines the strict execution boundaries for AI workers modifying `BYPASS-FORGE`.

## Shell Security
* Enforce `shell=False` across all Python `subprocess` invocations.
* Mandate `shlex.split()` tokenization for any command arguments.

## Scope Isolation
* Restrict automated edits to payload generation logic in `bypass_forge/`, unit tests in `tests/`, and workflow definitions.
* Do not modify core infrastructure outside of these designated zones unless explicitly instructed by a verified human maintainer.

## Credential & Leak Prevention
* Explicitly prohibit printing or persisting raw authorization tokens, external target URLs, or full stack traces (`str(e)` / `exc_info=True`) in logs or triage artifacts.
* All error messages must be sanitized and free of sensitive environment context.
