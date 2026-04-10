#!/usr/bin/env bash
# =============================================================================
# Bountyscope "Surgical Strike" Pipeline — recon_to_analysis.sh
# Version : 2.0.0
# Author  : @lucius-log
# Purpose : WPScan plugin discovery → Semgrep security/credential analysis
# Usage   : ./recon_to_analysis.sh <target_url> [--skip-wpscan]
#
# Dependencies: wpscan, jq, semgrep
# Credentials : WPSCAN_API_KEY must be set in env or ~/.wpscan/token
# =============================================================================
set -euo pipefail
IFS=$'\n\t'
 
# -----------------------------------------------------------------------------
# CONSTANTS & DEFAULTS
# -----------------------------------------------------------------------------
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readonly TIMESTAMP="$(date +%F_%H-%M-%S)"
readonly BASE_WORKSPACE="${BOUNTYSCOPE_WORKSPACE:-${SCRIPT_DIR}/workspace}"
readonly LATEST_LINK="${BASE_WORKSPACE}/latest_scan"
readonly CACHE_DIR="${SCRIPT_DIR}/cache/plugins"

# Dynamically set OUTPUT_DIR and LOG_FILE depending on --skip-wpscan
if [[ "$*" == *--skip-wpscan* ]]; then
    # Use latest_scan symlink as workspace/output dir
    if [[ -L "$LATEST_LINK" ]]; then
        OUTPUT_DIR="$(readlink "$LATEST_LINK")"
    else
        echo "[!] latest_scan symlink not found. Aborting." >&2
        exit 1
    fi
else
    OUTPUT_DIR="${BASE_WORKSPACE}/${TIMESTAMP}"
fi

readonly LOG_FILE="${OUTPUT_DIR}/pipeline.log"
readonly WPSCAN_RESULT="${OUTPUT_DIR}/wpscan_results.json"
 
# Semgrep rulesets — extend as needed
readonly SEMGREP_CONFIGS=(
    "p/security-audit"
    "p/secrets"
    "p/php"
    "p/wordpress"
)
 
# Colours (disabled automatically if not a tty)
if [[ -t 1 ]]; then
    C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'
    C_YELLOW='\033[0;33m'; C_CYAN='\033[0;36m'; C_BOLD='\033[1m'
else
    C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_CYAN=''; C_BOLD=''
fi
 

# -----------------------------------------------------------------------------
# Ensure workspace output directory exists before logging
# -----------------------------------------------------------------------------
ensure_log_dir() {
    mkdir -p "$(dirname \"${LOG_FILE}\")"
}

# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------
log() {
    ensure_log_dir
    local level="$1"; shift
    local message="$*"
    local ts; ts="$(date +%T)"
    local prefix

    case "$level" in
        INFO)  prefix="${C_CYAN}[*]${C_RESET}" ;;
        OK)    prefix="${C_GREEN}[✓]${C_RESET}" ;;
        WARN)  prefix="${C_YELLOW}[!]${C_RESET}" ;;
        ERROR) prefix="${C_RED}[✗]${C_RESET}" ;;
        FIND)  prefix="${C_BOLD}${C_RED}[FIND]${C_RESET}" ;;
        *)     prefix="[?]" ;;
    esac

    local line="${ts} ${prefix} ${message}"
    echo -e "${line}"
    # Strip ANSI codes when writing to log file
    echo -e "${line}" | sed 's/\x1b\[[0-9;]*m//g' >> "${LOG_FILE}"
}
 
# -----------------------------------------------------------------------------
# USAGE & ARGUMENT PARSING
# -----------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} <target_url> [options]
 
Options:
  --skip-wpscan    Use existing wpscan_results.json from latest_scan/ (dev mode)
  --help           Show this help message
 
Environment:
  WPSCAN_API_KEY        WPScan API token (preferred over file-based)
  BOUNTYSCOPE_WORKSPACE Override workspace root (default: ./workspace)
 
Examples:
  ${SCRIPT_NAME} https://target.example.com
  ${SCRIPT_NAME} https://target.example.com --skip-wpscan
EOF
    exit 0
}
 
SKIP_WPSCAN=false
 
parse_args() {
    if [[ $# -lt 1 ]]; then
        log ERROR "Missing required argument: <target_url>"
        usage
    fi
 
    TARGET="$1"; shift
 
    # Validate URL format (basic sanity check)
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        log ERROR "TARGET must begin with http:// or https:// — got: '${TARGET}'"
        exit 1
    fi
 
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-wpscan) SKIP_WPSCAN=true ;;
            --help)        usage ;;
            *) log WARN "Unknown option: '$1' — ignoring"; ;;
        esac
        shift
    done
}
 
# -----------------------------------------------------------------------------
# DEPENDENCY CHECKS
# -----------------------------------------------------------------------------
check_dependencies() {
    local -a required=("wpscan" "jq" "semgrep")
    local missing=()
 
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
 
    if [[ ${#missing[@]} -gt 0 ]]; then
        log ERROR "Missing required tools: ${missing[*]}"
        log ERROR "Install them and retry."
        exit 1
    fi
}
 
# -----------------------------------------------------------------------------
# API KEY RESOLUTION
# Precedence: env var → ~/.wpscan/token → fail
# Key is NEVER passed as a CLI argument to avoid exposure in `ps aux`
# -----------------------------------------------------------------------------
resolve_api_key() {
    if [[ -n "${WPSCAN_API_KEY:-}" ]]; then
        log INFO "WPScan API key loaded from environment."
        return
    fi
 
    local token_file="${HOME}/.wpscan/token"
    if [[ -f "$token_file" ]]; then
        WPSCAN_API_KEY="$(< "$token_file")"
        WPSCAN_API_KEY="${WPSCAN_API_KEY//[[:space:]]/}"  # strip whitespace
        log INFO "WPScan API key loaded from ${token_file}."
        return
    fi
 
    log ERROR "No WPScan API key found."
    log ERROR "Set WPSCAN_API_KEY env var or create ~/.wpscan/token"
    exit 1
}
 
# -----------------------------------------------------------------------------
# WORKSPACE SETUP
# -----------------------------------------------------------------------------
setup_workspace() {
    if [[ "$SKIP_WPSCAN" == true ]]; then
        mkdir -p "$OUTPUT_DIR" "$CACHE_DIR"
        log INFO "Workspace : ${OUTPUT_DIR}"
        log INFO "Symlink   : ${LATEST_LINK} → ${OUTPUT_DIR}"
        log INFO "Log file  : ${LOG_FILE}"
    else
        mkdir -p "$OUTPUT_DIR" "$CACHE_DIR"
        # Update symlink: workspace/latest_scan → current timestamped dir
        ln -sfn "$OUTPUT_DIR" "$LATEST_LINK"
        log INFO "Workspace : ${OUTPUT_DIR}"
        log INFO "Symlink   : ${LATEST_LINK} → ${OUTPUT_DIR}"
        log INFO "Log file  : ${LOG_FILE}"
    fi
}
 
# -----------------------------------------------------------------------------
# WPSCAN — Plugin Discovery
# -----------------------------------------------------------------------------

run_wpscan() {
    if [[ "$SKIP_WPSCAN" == true ]]; then
        local fallback="${LATEST_LINK}/wpscan_results.json"
        if [[ -f "$fallback" ]]; then
            log WARN "--skip-wpscan set. Copying existing results from latest_scan/."
            # Only copy if source and destination are not the same file
            if [ "$fallback" -ef "$WPSCAN_RESULT" ]; then
                log INFO "Source and destination for WPScan results are identical. Skipping copy."
            else
                cp "$fallback" "$WPSCAN_RESULT"
            fi
            return
        else
            log ERROR "--skip-wpscan set but no prior results found at ${fallback}"
            exit 1
        fi
    fi
 
    log INFO "Running WPScan against: ${TARGET}"
 
    # wpscan reads the token from stdin-equivalent env var, never from a CLI flag
    if ! wpscan \
            --url "$TARGET" \
            --enumerate p \
            --plugins-detection aggressive \
            --format json \
            --api-token "$WPSCAN_API_KEY" \
            --output "$WPSCAN_RESULT" \
            2>>"${OUTPUT_DIR}/wpscan_stderr.log"; then
 
        log WARN "WPScan exited with a non-zero status. Checking for partial output..."
        if [[ ! -s "$WPSCAN_RESULT" ]]; then
            log ERROR "WPScan produced no output. Check ${OUTPUT_DIR}/wpscan_stderr.log"
            exit 1
        fi
        log WARN "Partial WPScan output found — continuing with caution."
    fi
 
    log OK "WPScan complete. Results: ${WPSCAN_RESULT}"
}
 
# -----------------------------------------------------------------------------
# PLUGIN EXTRACTION
# -----------------------------------------------------------------------------
extract_plugins() {
    if ! jq -e '.plugins' "$WPSCAN_RESULT" &>/dev/null; then
        log WARN "No 'plugins' key in WPScan output. Target may not be WordPress."
        exit 0
    fi
 
    mapfile -t PLUGINS < <(jq -r '.plugins | keys[]' "$WPSCAN_RESULT")
 
    if [[ ${#PLUGINS[@]} -eq 0 ]]; then
        log WARN "WPScan found no plugins to analyse."
        exit 0
    fi
 
    log INFO "Discovered ${#PLUGINS[@]} plugin(s): ${PLUGINS[*]}"
}
 
# -----------------------------------------------------------------------------
# SEMGREP ANALYSIS — Per Plugin
# -----------------------------------------------------------------------------
run_semgrep_on_plugin() {
    local plugin="$1"
    local plugin_path="${CACHE_DIR}/${plugin}"
    local audit_file="${OUTPUT_DIR}/${plugin}_audit.json"
 
    if [[ ! -d "$plugin_path" ]]; then
        log WARN "Source for '${plugin}' not in cache — run fetcher.py first. Skipping."
        return 0
    fi
 
    log INFO "Analysing: ${plugin}"
 
    # Build --config flags dynamically from the array
    local config_flags=()
    for ruleset in "${SEMGREP_CONFIGS[@]}"; do
        config_flags+=(--config "$ruleset")
    done
 
    local semgrep_stderr="${OUTPUT_DIR}/${plugin}_semgrep_stderr.log"
 
    if semgrep \
            "${config_flags[@]}" \
            --json \
            --output "$audit_file" \
            --metrics=off \
            "$plugin_path" \
            2>"$semgrep_stderr"; then
 
        # Parse finding count from Semgrep JSON output
        local finding_count
        finding_count="$(jq '.results | length' "$audit_file" 2>/dev/null || echo '?')"
 
        if [[ "$finding_count" == "0" ]]; then
            log OK "${plugin} — clean (0 findings)"
        else
            log FIND "${plugin} — ${finding_count} potential finding(s) → ${audit_file}"
        fi
    else
        log ERROR "Semgrep failed on ${plugin}. Check ${semgrep_stderr}"
    fi
}
 
# -----------------------------------------------------------------------------
# PIPELINE SUMMARY
# -----------------------------------------------------------------------------
print_summary() {
    local total=${#PLUGINS[@]}
    local cached=0
 
    for plugin in "${PLUGINS[@]}"; do
        [[ -d "${CACHE_DIR}/${plugin}" ]] && ((cached++)) || true
    done
 
    local analysed="$cached"
    local skipped=$(( total - cached ))
 
    echo ""
    log INFO "════════════════════════════════════"
    log INFO " Pipeline Summary"
    log INFO "════════════════════════════════════"
    log INFO " Target    : ${TARGET}"
    log INFO " Plugins   : ${total} discovered"
    log INFO " Analysed  : ${analysed}"
    log INFO " Skipped   : ${skipped} (not in cache — run fetcher.py)"
    log INFO " Output    : ${OUTPUT_DIR}"
    log INFO " Latest    : ${LATEST_LINK}"
    log INFO "════════════════════════════════════"
}
 
# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------
main() {
    parse_args "$@"
    check_dependencies
    setup_workspace

    log INFO "Initialising Bountyscope Surgical Strike on: ${TARGET}"

    if [[ "$SKIP_WPSCAN" == true ]]; then
        run_wpscan
    else
        resolve_api_key
        run_wpscan
    fi
    extract_plugins

    local analysed=0
    for plugin in "${PLUGINS[@]}"; do
        run_semgrep_on_plugin "$plugin"
        ((analysed++)) || true
    done

    print_summary
    log OK "Pipeline complete. Review findings in: ${OUTPUT_DIR}"
}
 
main "$@"
