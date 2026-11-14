#!/usr/bin/env bash
# Runs @sphior/scan for the action and hands the result to report.mjs.
#
# Inputs arrive as environment variables (never interpolated into this script) and are
# validated before use. Exit codes of the scanner:
#   0 = nothing reached the threshold, 1 = a finding reached it, 2 = nothing was scanned.
# A 1 does not fail this step: the SARIF still has to be uploaded, so the gate is a later step.
set -euo pipefail

fail() { echo "::error title=SPHIOR CODE::$1"; exit 2; }

# ── Validate inputs ─────────────────────────────────────────────────────────
[[ "$SPHIOR_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] \
  || fail "version must be an exact version such as 0.1.9, got '$SPHIOR_VERSION'."

fail_on="$(printf '%s' "$SPHIOR_FAIL_ON" | tr '[:upper:]' '[:lower:]')"
case "$fail_on" in
  critical|high|medium|low|info|none) ;;
  *) fail "fail-on must be critical, high, medium, low, info or none, got '$SPHIOR_FAIL_ON'." ;;
esac

case "$SPHIOR_UPLOAD" in
  auto|true|false) ;;
  *) fail "upload-sarif must be auto, true or false, got '$SPHIOR_UPLOAD'." ;;
esac

workspace="${GITHUB_WORKSPACE:-$PWD}"
scan_dir="$(cd "$workspace" && cd -- "$SPHIOR_PATH" 2>/dev/null && pwd -P)" \
  || fail "path '$SPHIOR_PATH' does not exist in the repository."
case "$scan_dir/" in
  "$(cd "$workspace" && pwd -P)/"*) ;;
  *) fail "path '$SPHIOR_PATH' is outside the repository." ;;
esac

sarif="$SPHIOR_SARIF"
[[ "$sarif" = /* ]] || sarif="$workspace/$sarif"
mkdir -p "$(dirname -- "$sarif")"

# ── Scan ─────────────────────────────────────────────────────────────────────
args=(run "$scan_dir" --sarif "$sarif")
[[ "$fail_on" != "none" ]] && args+=(--fail-on "$fail_on")

set +e
npx --yes "@sphior/scan@${SPHIOR_VERSION}" "${args[@]}"
code=$?
set -e

if [[ "$code" -ne 0 && "$code" -ne 1 ]]; then
  fail "the scan did not run (exit $code). Check the message above."
fi
[[ -s "$sarif" ]] || fail "the scan finished but wrote no SARIF report."

# ── Report: rewrite paths, count, summary, outputs ──────────────────────────
SPHIOR_SCAN_DIR="$scan_dir" SPHIOR_WORKSPACE="$workspace" SPHIOR_SARIF_ABS="$sarif" \
SPHIOR_FAIL_ON_NORM="$fail_on" SPHIOR_EXIT="$code" \
  node "$GITHUB_ACTION_PATH/scripts/report.mjs"

# ── Upload decision ─────────────────────────────────────────────────────────
upload=false
case "$SPHIOR_UPLOAD" in
  true) upload=true ;;
  auto) [[ "${SPHIOR_REPO_PRIVATE:-}" == "false" ]] && upload=true ;;
esac
{
  echo "upload=$upload"
  echo "sarif-file=$sarif"
  [[ "$code" -eq 1 ]] && echo "gate=fail" || echo "gate=pass"
} >> "$GITHUB_OUTPUT"
