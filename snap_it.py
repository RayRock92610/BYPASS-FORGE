import subprocess
import sys
import os
import shutil
from pathlib import Path

def capture_local(source_file):
    # 1. Logic Gate: Find the browser
    chrome_path = shutil.which("chromium") or shutil.which("chromium-browser")
    
    if not chrome_path:
        print("[!] Error: Chromium not found. Run: pkg install chromium")
        return

    if not os.path.exists(source_file):
        print(f"[-] Missing: {source_file}")
        return

    output_dir = Path("./assets/snaps")
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir.absolute() / f"{Path(source_file).stem}.png"

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

    print(f"[*] Dragon-Forge: Using {chrome_path}")

    # 2. Production-Grade CLI Call
    cmd = [
        chrome_path,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        f"--screenshot={out_path}",
        "--window-size=1280,720",
        "--virtual-time-budget=10000", # Gives time for styles to load
        str(html_path.absolute())
    ]

    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print(f"[+] SUCCESS: Image deployed to {out_path}")
        if os.path.exists(html_path): os.remove(html_path)
    except subprocess.CalledProcessError as e:
        print(f"[!] Forge Failed: {e.stderr.decode()}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 snap_it.py <file>")
    else:
        capture_local(sys.argv[1])
