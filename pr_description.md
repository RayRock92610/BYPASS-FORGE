🎯 **What:** The code health issue addressed
Refactored the complex `capture_local` function in `snap_it.py` into smaller, logically separated helper functions (`find_browser`, `generate_html`, and `run_browser`).

💡 **Why:** How this improves maintainability
The original monolithic function was doing too much: discovering the browser executable path, creating the output directory and HTML wrapper, reading and escaping the code snippet, and finally calling the browser via `subprocess`. Breaking it down into modular pieces makes the code far easier to digest, test independently, and reuse if needed. It separates the concerns of resolving dependencies, preparing input data (HTML), and the actual execution (Chromium headless mode).

✅ **Verification:** How you confirmed the change is safe
I ran linters (specifically `flake8` with the project's required select flags) to make sure there are no syntax or undefined name errors. I also ran `pytest` on the test suite to ensure nothing else in the repository broke. The command formatting logic and parameters passed to `subprocess.run` (including `shlex` and `shell=False`) were faithfully preserved from the original logic while keeping explicit exception chaining intact.

✨ **Result:** The improvement achieved
A cleaner, much more readable, and strictly standard-adhering script that does not change the core behavior but significantly improves code organization.
