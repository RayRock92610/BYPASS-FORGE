#!/usr/bin/env bash
set -e

echo "=== Running Witch Hunter Security Gate ==="

# 1. Run Python AST Static Analyzer if present
if [ -f "scripts/ci/witch_hunter_ast.py" ] && command -v python3 >/dev/null 2>&1; then
  echo "[AST SCAN] Executing scripts/ci/witch_hunter_ast.py..."
  python3 scripts/ci/witch_hunter_ast.py
fi

# 2. Validate witch-report.json format and vulnerability counts
if [ -f "witch-report.json" ]; then
  if command -v jq >/dev/null 2>&1; then
    HIGH_CRIT=$(jq '[.vulnerabilities[]? | select(.severity == "HIGH" or .severity == "CRITICAL")] | length' witch-report.json 2>/dev/null || echo 0)
    if [ "$HIGH_CRIT" -gt 0 ]; then
      echo "[FAIL] witch-report.json contains $HIGH_CRIT High/Critical vulnerabilities."
      exit 1
    fi
  fi
fi

echo "[PASS] Witch Hunter gate passed successfully."
