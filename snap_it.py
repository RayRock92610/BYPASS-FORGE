#!/usr/bin/env python3
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

# MIT License
#
# Copyright (c) 2026 Ray
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


def find_browser():
    """Finds the path to the Chromium browser."""
    return shutil.which("chromium") or shutil.which("chromium-browser")


def generate_html(source_file, output_dir):
    """Generates the HTML file containing the code."""
    with open(source_file, 'r') as f:
        code = f.read().replace('<', '&lt;').replace('>', '&gt;')

    html_path = output_dir / "temp.html"
    html_content = f"""
    <html>
    <body style="background: #0d1117; margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh;">
        <div style="background: #161b22; padding: 40px; border-radius: 12px; border: 1px solid #30363d; color: #c9d1d9; font-family: monospace; font-size: 20px; box-shadow: 0 20px 50px rgba(0,0,0,0.5);">
            <pre style="margin: 0;">{code}</pre>
        </div>
    </body>
    </html>
    """
    with open(html_path, 'w') as f:
        f.write(html_content)

    return html_path


def run_browser(chrome_path, html_path, out_path):
    """Runs the headless browser to capture the screenshot."""
    print(f"[*] Dragon-Forge: Using {chrome_path}")

    # Enforce shell=False and use shlex.split() as per project guidelines
    cmd_str = f"{shlex.quote(chrome_path)} --headless --disable-gpu --no-sandbox --screenshot={shlex.quote(str(out_path))} --window-size=1280,720 --virtual-time-budget=10000 {shlex.quote(str(html_path.absolute()))}"
    cmd = shlex.split(cmd_str)

    try:
        subprocess.run(cmd, check=True, capture_output=True, shell=False)
        print(f"[+] SUCCESS: Image deployed to {out_path}")
        if os.path.exists(html_path):
            os.remove(html_path)
    except subprocess.CalledProcessError as e:
        print(f"[!] Forge Failed: {e.stderr.decode()}")


def capture_local(source_file):
    # 1. Logic Gate: Find the browser
    chrome_path = find_browser()

    if not chrome_path:
        print("[!] Error: Chromium not found. Run: pkg install chromium")
        return

    if not os.path.exists(source_file):
        print(f"[-] Missing: {source_file}")
        return

    output_dir = Path("./assets/snaps")
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir.absolute() / f"{Path(source_file).stem}.png"

    html_path = generate_html(source_file, output_dir)
    run_browser(chrome_path, html_path, out_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 snap_it.py <file>")
    else:
        capture_local(sys.argv[1])
