#!/bin/zsh

set -euo pipefail

SCRIPT_DIR=${0:A:h}
PYTHON_BIN=${PYTHON_BIN:-"$SCRIPT_DIR/.venv/bin/python"}

if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="/usr/bin/python3"
fi

TARGET=${TARGET:-"http://fluent-test.local"}
PLUGIN=${PLUGIN:-"fluentcrm"}
OBJECT_ID=${OBJECT_ID:-"1"}
JSON_OUT=${JSON_OUT:-"fluent-crm-idor-local.json"}
MARKDOWN_OUT=${MARKDOWN_OUT:-"fluent-crm-idor-local.md"}
SKIP_WRITE=${SKIP_WRITE:-"1"}            # set to "" to enable PUT/POST
CONFIRM_DESTRUCTIVE=${CONFIRM_DESTRUCTIVE:-""}  # set to "1" to also enable DELETE

ATTACKER_COOKIE=${ATTACKER_COOKIE:-"REPLACE_WITH_CRM_AGENT_B_COOKIE"}
ATTACKER_NONCE=${ATTACKER_NONCE:-"REPLACE_WITH_CRM_AGENT_B_NONCE"}
VICTIM_COOKIE=${VICTIM_COOKIE:-"REPLACE_WITH_ADMIN_COOKIE"}
VICTIM_NONCE=${VICTIM_NONCE:-"REPLACE_WITH_ADMIN_NONCE"}

if [[ "$ATTACKER_COOKIE" == REPLACE_* || "$ATTACKER_NONCE" == REPLACE_* || "$VICTIM_COOKIE" == REPLACE_* || "$VICTIM_NONCE" == REPLACE_* ]]; then
  echo "Replace the ATTACKER_* and VICTIM_* placeholders in the environment or in run_idor_local.sh before running."
  exit 1
fi

echo "Using Python: $PYTHON_BIN"
echo "Target: $TARGET"

SKIP_WRITE_FLAG=()
[[ -n "$SKIP_WRITE" ]] && SKIP_WRITE_FLAG=(--skip-write)

DESTRUCTIVE_FLAG=()
[[ -n "$CONFIRM_DESTRUCTIVE" ]] && DESTRUCTIVE_FLAG=(--confirm-destructive)

exec "$PYTHON_BIN" "$SCRIPT_DIR/idor_scanner.py" \
  --target         "$TARGET" \
  --plugin         "$PLUGIN" \
  --object-id      "$OBJECT_ID" \
  --attacker-cookie "$ATTACKER_COOKIE" \
  --attacker-nonce  "$ATTACKER_NONCE" \
  --victim-cookie   "$VICTIM_COOKIE" \
  --victim-nonce    "$VICTIM_NONCE" \
  --json-out        "$JSON_OUT" \
  --markdown-out    "$MARKDOWN_OUT" \
  "${SKIP_WRITE_FLAG[@]}" \
  "${DESTRUCTIVE_FLAG[@]}"