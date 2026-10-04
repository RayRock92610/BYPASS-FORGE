import os
import sqlite3
import subprocess


def test_kfb1_optimization(tmp_path):
    # kfb1 overrides DB_PATH with $HOME/kessel-flow-system/...
    # so we need to read it from there

    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env["FWE_SECRET"] = "A_VALID_SECRET_THAT_IS_LONG_ENOUGH_12345"

    test_sh = tmp_path / "run_test.sh"
    with open(test_sh, "w") as f:
        f.write(f"""#!/bin/bash
export UA="Mozilla/5.0"
export OMEGA_KEY="7891"

sed '/main "\\$@"/d' $(pwd)/kfb1.sh > {tmp_path}/kfb1_lib.sh
source {tmp_path}/kfb1_lib.sh

init_db
mkdir -p "$CASE_ROOT/test_cid/intake"
echo "http://localhost:1111" > "$CASE_ROOT/test_cid/intake/subs.txt"

echo "7891" | deploy_strikeforce "test_cid"
""")
    os.chmod(test_sh, 0o755)

    curl_mock = tmp_path / "curl"
    with open(curl_mock, "w") as f:
        f.write("""#!/bin/bash
echo "Set-Cookie: session=123"
""")
    os.chmod(curl_mock, 0o755)

    env["PATH"] = str(tmp_path) + ":" + env["PATH"]

    subprocess.run(["bash", test_sh], env=env, check=True)

    # DB path based on script
    db_path = tmp_path / "kessel-flow-system/data/kessel_vault.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM findings")
    rows = cursor.fetchall()

    assert len(rows) == 1
    assert rows[0][1] == "test_cid"
    assert rows[0][2] == "INQUISITOR"
    assert rows[0][3] == "http://localhost:1111"
    assert "Set-Cookie: session=123" in rows[0][4]
