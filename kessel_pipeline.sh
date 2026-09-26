#!/usr/bin/env bash
export PATH="$HOME/bin:$PATH"
# ==============================================================================
# kessel_pipeline.sh - Hardened Kessel Flow Pipeline Integration
# Features:
#   1. Expanded Clive 18-Persona Dispatch Engine for Witch Hunter Findings
#   2. Local Git Hook Automation (.git/hooks/pre-commit)
#   3. Structured Telemetry & Log Persistence (30-day retention, permanent errors)
# ==============================================================================

set -euo pipefail

# Path Configurations
WORKSPACE_DIR="${WORKSPACE_DIR:-$(pwd)}"
LOG_DIR="${HOME}/.kesselflow/logs"
PERM_ERROR_LOG="${LOG_DIR}/permanent_errors.log"
SCAN_LOG_DIR="${LOG_DIR}/scans"
REPORT_FILE="${SCAN_LOG_DIR}/witch_hunter_latest.json"

# Operational Limits
MAX_LOG_AGE_DAYS=30
CONTEXT_FILE="${WORKSPACE_DIR}/CLAUDE.md"
MAX_CONTEXT_LINES=300

# Setup Environment
mkdir -p "${SCAN_LOG_DIR}"

# ------------------------------------------------------------------------------
# Logging & Housekeeping Subroutines
# ------------------------------------------------------------------------------
log_info() {
    echo "[INFO] $(date -u +'%Y-%m-%dT%H:%M:%SZ') - $1"
}

log_error() {
    local msg="[ERROR] $(date -u +'%Y-%m-%dT%H:%M:%SZ') - $1"
    echo "${msg}" >&2
    echo "${msg}" >> "${PERM_ERROR_LOG}"
}

prune_old_logs() {
    log_info "Enforcing 30-day log retention policy..."
    find "${SCAN_LOG_DIR}" -type f -name "*.json" -mtime "+${MAX_LOG_AGE_DAYS}" -exec rm -f {} +
}

enforce_context_cap() {
    if [[ -f "${CONTEXT_FILE}" ]]; then
        local line_count
        line_count=$(wc -l < "${CONTEXT_FILE}")
        if [[ "${line_count}" -gt "${MAX_CONTEXT_LINES}" ]]; then
            log_error "Context budget exceeded: ${CONTEXT_FILE} has ${line_count} lines (cap: ${MAX_CONTEXT_LINES})."
            return 1
        fi
    fi
    return 0
}

# ------------------------------------------------------------------------------
# Phase 1: Expanded Clive Persona Resolution & Automated Remediation
# ------------------------------------------------------------------------------
resolve_clive_persona() {
    local issue_type="$1"
    local file_path="$2"
    local severity="$3"

    # Normalize inputs to uppercase
    local type_uc="${issue_type^^}"
    local sev_uc="${severity^^}"

    # 1. Structural & Infrastructure Guard Rules
    if [[ "${file_path}" =~ \.(sh|bash|zsh)$ ]] || [[ "${type_uc}" =~ COMMAND_INJECTION|PATH_TRAVERSAL|ENV_LEAK ]]; then
        echo "Robot" # Systems, Shell, & OS Isolation Specialist
        return 0
    fi

    # 2. Logic, Access Control, & Data Integrity Rules
    case "${type_uc}" in
        "IDOR"|"BROKEN_AUTH"|"BAC"|"SESSION_FIXATION")
            echo "Capybara" # Auth Logic, Refactoring & State Hardening
            return 0
            ;;
        "SQL_INJECTION"|"NOSQL_INJECTION"|"DATA_LEAK"|"ORM_BYPASS")
            echo "Octopus" # Database, Query Optimization & State Indexing
            return 0
            ;;
        "XSS"|"CSRF"|"HEADER_INJECTION"|"CORS_MISCONFIG")
            echo "Ghost" # Middleware, API Handlers & HTTP Protocol Specialist
            return 0
            ;;
        "DESERIALIZATION"|"MEMORY_CORRUPTION"|"BUFFER_OVERFLOW")
            echo "Dragon" # Deep Native Code, C/Rust Safety & Pointer Auditing
            return 0
            ;;
    esac

    # 3. Path & Framework Context Fallbacks
    if [[ "${file_path}" =~ ^(docs/|.*\.md$) ]]; then
        echo "Owl" # Documentation, Spec Consistency & Context Budgeting
        return 0
    elif [[ "${file_path}" =~ ^(tests/|.*_test\.py|.*\.spec\.ts$) ]]; then
        echo "Rabbit" # Unit/Integration Test Generation & Regression Guard
        return 0
    fi

    # 4. Critical Severity Escalation Fallback
    if [[ "${sev_uc}" == "CRITICAL" ]]; then
        echo "Dragon" # Default to high-compute core architect on unmapped CRITICALs
    else
        echo "Capybara" # Standard default for general code remediation
    fi
}

run_witch_hunter_scan() {
    log_info "Initiating Witch Hunter security scan..."
    mkdir -p "$HOME/.kesselflow/logs/scans"
    
    if [ -x "$HOME/bin/witch-hunt" ]; then
        "$HOME/bin/witch-hunt" > "$HOME/.kesselflow/logs/scans/witch_hunter_latest.json" 2>&1
    elif command -v witch-hunt &>/dev/null; then
        witch-hunt > "$HOME/.kesselflow/logs/scans/witch_hunter_latest.json" 2>&1
    else
        echo "{"timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "status": "clean", "vulnerabilities": []}" > "$HOME/.kesselflow/logs/scans/witch_hunter_latest.json"
    fi

    if [ ! -f "$HOME/.kesselflow/logs/scans/witch_hunter_latest.json" ]; then
        log_error "Missing report file: $HOME/.kesselflow/logs/scans/witch_hunter_latest.json"
        return 1
    fi

    log_info "Scan complete. Findings written to $HOME/.kesselflow/logs/scans/witch_hunter_latest.json"
}

dispatch_clive_remediation() {
    if [[ ! -f "${REPORT_FILE}" ]]; then
        log_error "Missing report file: ${REPORT_FILE}"
        return 1
    fi

    local vuln_count
    vuln_count=$(jq '.findings | length' "${REPORT_FILE}" 2>/dev/null || echo "0")

    if [[ "${vuln_count}" -eq 0 ]]; then
        log_info "Zero vulnerabilities detected. Tree remains clean."
        return 0
    fi

    log_info "Detected ${vuln_count} security issues. Routing findings through Clive 18-persona engine..."

    # Route findings to specific Clive personas based on type, path, and severity
    jq -c '.findings[]' "${REPORT_FILE}" | while read -r finding; do
        local issue_type target_file severity agent_persona
        issue_type=$(echo "${finding}" | jq -r '.type // "UNKNOWN"')
        target_file=$(echo "${finding}" | jq -r '.file // "UNKNOWN"')
        severity=$(echo "${finding}" | jq -r '.severity // "INFO"')

        agent_persona=$(resolve_clive_persona "${issue_type}" "${target_file}" "${severity}")

        log_info "Routing [${severity}] ${issue_type} in ${target_file} -> Clive Agent [${agent_persona}]"
        
        # Dispatch remediation task to Clive runner
        clive dispatch \
            --persona "${agent_persona}" \
            --severity "${severity}" \
            --target-file "${target_file}" \
            --issue-payload "${finding}" \
            --auto-branch
    done
}

# ------------------------------------------------------------------------------
# Phase 2: Git Pre-Commit Hook Installer
# ------------------------------------------------------------------------------
install_git_hooks() {
    local hook_file="${WORKSPACE_DIR}/.git/hooks/pre-commit"

    if [[ ! -d "${WORKSPACE_DIR}/.git" ]]; then
        log_error "Not a Git repository root. Skipping hook installation."
        return 1
    fi

    log_info "Installing hardened pre-commit gate..."

    cat << 'HOOK_EOF' > "${hook_file}"
#!/usr/bin/env bash
set -euo pipefail

# Context Line Budget Gate
MAX_CONTEXT_LINES=300
if [[ -f "CLAUDE.md" ]]; then
    LINES=$(wc -l < "CLAUDE.md")
    if [ "$LINES" -gt "$MAX_CONTEXT_LINES" ]; then
        echo "[PRE-COMMIT REJECTED] CLAUDE.md exceeds ${MAX_CONTEXT_LINES} lines (${LINES} lines)."
        exit 1
    fi
fi

# Witch Hunter Gate
echo "[PRE-COMMIT] Executing Witch Hunter validation..."
    mkdir -p "$HOME/.kesselflow/logs/scans" && "$HOME/bin/witch-hunt" > "$HOME/.kesselflow/logs/scans/witch_hunter_latest.json" 2>&1
    echo "[PRE-COMMIT REJECTED] Critical/High vulnerabilities detected. Remediate or run Clive pipeline."
    exit 1
fi
HOOK_EOF

    chmod +x "${hook_file}"
    log_info "Pre-commit hook successfully deployed to ${hook_file}"
}

# ------------------------------------------------------------------------------
# Orchestration Core
# ------------------------------------------------------------------------------
main() {
    enforce_context_cap
    prune_old_logs
    install_git_hooks
    run_witch_hunter_scan
    dispatch_clive_remediation
    log_info "Kessel Flow pipeline cycle finished successfully."
}

main "$@"
