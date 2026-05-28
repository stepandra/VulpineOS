#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  FOXBRIDGE_CDP=19222 \
    scripts/agent-browser-foxbridge-baseline.sh

Required:
  FOXBRIDGE_CDP            Existing Foxbridge CDP endpoint or tunneled port,
                           e.g. 19222 or ws://127.0.0.1:9222. The harness
                           refuses to run without this so agent-browser cannot
                           launch its own Chromium by accident.
                           FOXBRIDGE_CDP_URL is accepted as a legacy alias.

Optional:
  EVIDENCE_DIR             Output directory. Default:
                           /tmp/autorecruit-agent-browser-foxbridge-<timestamp>
  TARGET_URL               Baseline page. Default: https://example.com
  RUN_SCANNERS=1           Also run fpscanner and CreepJS pages.
  FPSCANNER_URL            Default: https://ar-fpscanner-05280356.exe.xyz/
  CREEPJS_URL              Default: https://ar-creepjs-05280412.exe.xyz/
  AGENT_BROWSER_SESSION_ID agent-browser session. Default:
                           agent-browser-foxbridge-baseline-<timestamp>
  CAMOUFOX_BIN             Camoufox/firefox binary path for version capture.
  VULPINE_REMOTE_HEALTH_URL  Optional VulpineOS health endpoint to probe.
  VNC_HEALTH_URL           Optional noVNC/websockify URL to probe.
  BROWSER_VIEWER_URL       Optional Browser Viewer URL to probe.
  MATRIX_OS_HEALTH_URL     Optional matrix-os HTTP API URL to probe.

Outputs:
  report.md                Sanitized run summary with versions and step status.
  logs/*.log               Sanitized command output.
  screenshots/*.png        agent-browser screenshots.

Security notes:
  The report and logs redact the raw Foxbridge endpoint and URL credentials.
  Keep the evidence directory under /tmp unless a human explicitly chooses to
  copy sanitized artifacts into durable docs.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
workspace_root="$(cd "${repo_root}/.." && pwd)"

foxbridge_cdp="${FOXBRIDGE_CDP:-${FOXBRIDGE_CDP_URL:-}}"
if [[ -z "$foxbridge_cdp" ]]; then
  echo "ERROR: FOXBRIDGE_CDP is required; refusing to launch agent-browser without --cdp." >&2
  usage >&2
  exit 64
fi

if ! command -v agent-browser >/dev/null 2>&1; then
  echo "ERROR: agent-browser is not on PATH." >&2
  exit 69
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_dir="${EVIDENCE_DIR:-/tmp/autorecruit-agent-browser-foxbridge-${timestamp}}"
logs_dir="${evidence_dir}/logs"
screenshots_dir="${evidence_dir}/screenshots"
report="${evidence_dir}/report.md"
target_url="${TARGET_URL:-https://example.com}"
fpscanner_url="${FPSCANNER_URL:-https://ar-fpscanner-05280356.exe.xyz/}"
creepjs_url="${CREEPJS_URL:-https://ar-creepjs-05280412.exe.xyz/}"
session_name="${AGENT_BROWSER_SESSION_ID:-agent-browser-foxbridge-baseline-${timestamp}}"

mkdir -p "$logs_dir" "$screenshots_dir"

sanitize_file() {
  local file="$1"
  python3 - "$file" "$foxbridge_cdp" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
raw_endpoint = sys.argv[2]
text = path.read_text(errors="replace")
if raw_endpoint:
    text = text.replace(raw_endpoint, "<redacted-foxbridge-cdp>")
text = re.sub(r"(https?|wss?)://([^\s/@:]+):([^\s/@]+)@", r"\1://<redacted-credentials>@", text)
text = re.sub(r"\b127\.0\.0\.1:(\d+)\b", r"<loopback>:\1", text)
text = re.sub(r"\blocalhost:(\d+)\b", r"<loopback>:\1", text)
path.write_text(text)
PY
}

append_report() {
  printf '%s\n' "$*" >>"$report"
}

run_capture() {
  local name="$1"
  shift
  local logfile="${logs_dir}/${name}.log"
  append_report "- ${name}: running"
  set +e
  "$@" >"$logfile" 2>&1
  local status=$?
  set -e
  sanitize_file "$logfile"
  if [[ $status -eq 0 ]]; then
    append_report "  - status: PASS"
  else
    append_report "  - status: FAIL (${status})"
  fi
  append_report "  - log: logs/${name}.log"
  return 0
}

git_summary() {
  local label="$1"
  local dir="$2"
  if [[ -d "${dir}/.git" ]]; then
    local branch head dirty
    branch="$(git -C "$dir" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
    head="$(git -C "$dir" rev-parse HEAD 2>/dev/null || echo unknown)"
    if [[ -n "$(git -C "$dir" status --short 2>/dev/null || true)" ]]; then
      dirty="dirty"
    else
      dirty="clean"
    fi
    append_report "- ${label}: branch=${branch}, head=${head}, worktree=${dirty}"
  else
    append_report "- ${label}: not found at ${dir}"
  fi
}

probe_url() {
  local name="$1"
  local url="$2"
  [[ -n "$url" ]] || return 0
  run_capture "probe-${name}" curl -fsS -I --max-time 5 "$url"
}

foxbridge_http_url() {
  python3 - "$foxbridge_cdp" <<'PY'
from urllib.parse import urlsplit, urlunsplit
import sys

endpoint = sys.argv[1]
if endpoint.isdigit():
    print(f"http://127.0.0.1:{endpoint}/json/version")
    raise SystemExit(0)
u = urlsplit(endpoint)
scheme = "https" if u.scheme == "wss" else "http"
if not u.netloc:
    raise SystemExit(0)
print(urlunsplit((scheme, u.netloc, "/json/version", "", "")))
PY
}

cat >"$report" <<EOF
# agent-browser × Foxbridge/VulpineOS A0 baseline

- run_id: ${timestamp}
- evidence_dir: ${evidence_dir}
- target_url: ${target_url}
- foxbridge_cdp: <redacted-foxbridge-cdp>
- session: ${session_name}

## Versions and source revisions

EOF

append_report "- agent-browser: $(agent-browser --version 2>/dev/null || echo unavailable)"
git_summary "AutoRecruit monorepo" "$workspace_root"
git_summary "VulpineOS checkout" "$repo_root"
git_summary "Sibling foxbridge checkout" "${workspace_root}/foxbridge"
git_summary "Sibling vulpineos-docs checkout" "${workspace_root}/vulpineos-docs"

if [[ -n "${CAMOUFOX_BIN:-}" ]]; then
  run_capture camoufox-version "$CAMOUFOX_BIN" --version
else
  append_report "- Camoufox binary: not captured (set CAMOUFOX_BIN to record it)"
fi

append_report ""
append_report "## Service probes"

if cdp_version_url="$(foxbridge_http_url 2>/dev/null)" && [[ -n "$cdp_version_url" ]]; then
  probe_url foxbridge-json-version "$cdp_version_url"
else
  append_report "- foxbridge-json-version: not probed; could not derive HTTP /json/version URL"
fi
probe_url vulpine-remote "${VULPINE_REMOTE_HEALTH_URL:-}"
probe_url vnc "${VNC_HEALTH_URL:-}"
probe_url browser-viewer "${BROWSER_VIEWER_URL:-}"
probe_url matrix-os "${MATRIX_OS_HEALTH_URL:-}"

run_capture local-listeners lsof -nP -iTCP -sTCP:LISTEN

append_report ""
append_report "## agent-browser smoke steps"
append_report ""
append_report "All steps use: agent-browser --cdp <redacted-foxbridge-cdp> --session ${session_name} ..."

ab=(agent-browser --cdp "$foxbridge_cdp" --session "$session_name")

run_capture example-open "${ab[@]}" open "$target_url"
run_capture example-get-url "${ab[@]}" get url
run_capture example-get-title "${ab[@]}" get title
run_capture example-eval-location "${ab[@]}" eval "window.location.href"
run_capture example-screenshot "${ab[@]}" screenshot "${screenshots_dir}/example.png"
run_capture example-snapshot-interactive "${ab[@]}" snapshot -i

if [[ "${RUN_SCANNERS:-0}" == "1" ]]; then
  append_report ""
  append_report "## Scanner pages"
  run_capture fpscanner-open "${ab[@]}" open "$fpscanner_url"
  run_capture fpscanner-wait "${ab[@]}" wait --load networkidle
  run_capture fpscanner-screenshot "${ab[@]}" screenshot "${screenshots_dir}/fpscanner.png"
  run_capture fpscanner-snapshot-interactive "${ab[@]}" snapshot -i

  run_capture creepjs-open "${ab[@]}" open "$creepjs_url"
  run_capture creepjs-wait "${ab[@]}" wait --load networkidle
  run_capture creepjs-screenshot "${ab[@]}" screenshot "${screenshots_dir}/creepjs.png"
  run_capture creepjs-snapshot-interactive "${ab[@]}" snapshot -i
else
  append_report ""
  append_report "## Scanner pages"
  append_report "- skipped: set RUN_SCANNERS=1 after proxy/persona preflight is safe."
fi

append_report ""
append_report "## Closeout"
run_capture close-session "${ab[@]}" close

append_report ""
append_report "## A0 interpretation checklist"
append_report ""
append_report "- open/screenshot green: inspect example-open and example-screenshot statuses above."
append_report "- snapshot pre-patch failure shape: inspect logs/example-snapshot-interactive.log."
append_report "- runtime context race: inspect example-get-url/title/eval statuses and logs."
append_report "- Vulpine/Camoufox proof: inspect foxbridge-json-version, Camoufox version, and screenshots; this harness never runs agent-browser without --cdp."
append_report "- raw endpoint hygiene: report/logs redact the Foxbridge endpoint and URL credentials."

sanitize_file "$report"

echo "A0 baseline complete: ${report}"
