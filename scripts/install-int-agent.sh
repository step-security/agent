#!/usr/bin/env bash
# Installs an int build of the agent from GHCR on a GitHub-hosted Linux runner,
# for testing before a release. It does what harden-runner's pre and post steps
# do for the agent, but reports to int. Use it instead of harden-runner, not
# with it: both install into /home/agent.
#
#   start [tag]   install and start ghcr.io/step-security/agent/agent-int:<tag>
#                 (default latest; also pr-<number>, dev-<branch> or a commit SHA)
#   stop          tell the agent the job is done and print its log
#
# Optional environment: EGRESS_POLICY (audit or block, default audit),
# ALLOWED_ENDPOINTS, DISABLE_FILE_MONITORING (true or false, default false).
#
# Example:
#   - run: curl -fsSL https://raw.githubusercontent.com/step-security/agent/int/scripts/install-int-agent.sh | bash -s -- start pr-506
#   - run: npm test
#   - if: always()
#     run: curl -fsSL https://raw.githubusercontent.com/step-security/agent/int/scripts/install-int-agent.sh | bash -s -- stop

set -euo pipefail

REPOSITORY="step-security/agent/agent-int"
API_URL="https://int.api.stepsecurity.io/v1"
TELEMETRY_URL="https://int.app-api.stepsecurity.io/v1"
WEB_URL="https://int1.stepsecurity.io"
AGENT_DIR="/home/agent"

fail() {
  echo "install-int-agent: $*" >&2
  exit 1
}

start() {
  local tag="${1:-latest}"
  [[ "$(uname -s)" == "Linux" ]] || fail "Linux runners only"
  [[ -n "${GITHUB_REPOSITORY:-}" && -n "${GITHUB_RUN_ID:-}" ]] || fail "run this inside a GitHub Actions job"
  [[ "$tag" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || fail "invalid tag: $tag"
  [[ ! -e "$AGENT_DIR/agent" ]] || fail "an agent is already installed in $AGENT_DIR"

  local arch
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
  local file="agent_linux_${arch}.tar.gz"

  local work
  work="$(mktemp -d)"

  local token
  token="$(curl -fsS "https://ghcr.io/token?scope=repository:${REPOSITORY}:pull" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"

  curl -fsS -H "Authorization: Bearer ${token}" \
    -H "Accept: application/vnd.oci.image.manifest.v1+json" \
    -o "$work/manifest.json" \
    "https://ghcr.io/v2/${REPOSITORY}/manifests/${tag}" ||
    fail "ghcr.io/${REPOSITORY}:${tag} not found"

  local digest revision
  read -r digest revision < <(python3 - "$work/manifest.json" "$file" <<'EOF'
import json, re, sys
manifest = json.load(open(sys.argv[1]))
layers = [l for l in manifest.get("layers", [])
          if l.get("annotations", {}).get("org.opencontainers.image.title") == sys.argv[2]]
if len(layers) != 1 or not re.fullmatch(r"sha256:[a-f0-9]{64}", layers[0]["digest"]):
    sys.exit(f"{sys.argv[2]} not found in the artifact")
revision = manifest.get("annotations", {}).get("org.opencontainers.image.revision", "unknown")
print(layers[0]["digest"], revision)
EOF
  )
  [[ -n "${digest:-}" ]] || fail "$file not found in ghcr.io/${REPOSITORY}:${tag}"

  echo "Installing ghcr.io/${REPOSITORY}:${tag} (commit ${revision}, ${file})"

  # curl does not send the Authorization header to the blob storage host GHCR
  # redirects to.
  curl -fsSL -H "Authorization: Bearer ${token}" -o "$work/$file" \
    "https://ghcr.io/v2/${REPOSITORY}/blobs/${digest}"
  local actual
  actual="sha256:$(sha256sum "$work/$file" | cut -d' ' -f1)"
  [[ "$actual" == "$digest" ]] || fail "digest mismatch for $file: expected $digest, got $actual"
  echo "Digest verified: $digest"

  tar -xzf "$work/$file" -C "$work" agent

  # Register the job with the int API, as harden-runner does, to get the key
  # the agent uses to send data.
  local correlation_id one_time_key=""
  correlation_id="$(cat /proc/sys/kernel/random/uuid)"
  local monitor
  monitor="$(curl -sS -m 5 -X POST -H "content-type: application/json" \
    -d "{\"correlation_id\":\"${correlation_id}\",\"job\":\"${GITHUB_JOB:-}\"}" \
    "${API_URL}/github/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/monitor" || true)"
  one_time_key="$(printf '%s' "$monitor" |
    python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("one_time_key", ""))
except Exception: print("")')"
  [[ -n "$one_time_key" ]] || echo "warning: int API did not return a one-time key; the agent will run but may not report"

  sudo mkdir -p "$AGENT_DIR"
  sudo chown "$(id -un)" "$AGENT_DIR"
  cp "$work/agent" "$AGENT_DIR/agent"
  chmod +x "$AGENT_DIR/agent"

  CORRELATION_ID="$correlation_id" ONE_TIME_KEY="$one_time_key" \
    API_URL="$API_URL" TELEMETRY_URL="$TELEMETRY_URL" \
    python3 - "$AGENT_DIR/agent.json" <<'EOF'
import json, os, sys
env = os.environ
private = False
try:
    private = json.load(open(env["GITHUB_EVENT_PATH"]))["repository"]["private"]
except Exception:
    pass
config = {
    "repo": env["GITHUB_REPOSITORY"],
    "run_id": env["GITHUB_RUN_ID"],
    "correlation_id": env["CORRELATION_ID"],
    "working_directory": env.get("GITHUB_WORKSPACE", ""),
    "api_url": env["API_URL"],
    "telemetry_url": env["TELEMETRY_URL"],
    "allowed_endpoints": env.get("ALLOWED_ENDPOINTS", ""),
    "denied_endpoints": "",
    "egress_policy": env.get("EGRESS_POLICY", "audit"),
    "disable_telemetry": False,
    "disable_sudo": False,
    "disable_sudo_and_containers": False,
    "disable_file_monitoring": env.get("DISABLE_FILE_MONITORING", "false") == "true",
    "private": private,
    "is_github_hosted": True,
    "is_debug": env.get("RUNNER_DEBUG") == "1",
    "one_time_key": env["ONE_TIME_KEY"],
    "deploy_on_self_hosted_vm": False,
}
with open(sys.argv[1], "w") as f:
    json.dump(config, f)
EOF

  sudo tee /etc/systemd/system/agent.service >/dev/null <<'EOF'
[Unit]
Description=Agent
After=network.target

[Service]
Type=simple
ExecStart=/home/agent/agent
WorkingDirectory=/home/agent
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=agentservice
AmbientCapabilities=CAP_NET_BIND_SERVICE, CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo service agent start

  for _ in $(seq 1 30); do
    [[ -f "$AGENT_DIR/agent.status" ]] && break
    sleep 1
  done
  if [[ -f "$AGENT_DIR/agent.status" ]]; then
    cat "$AGENT_DIR/agent.status"
    echo
  else
    echo "warning: agent did not write agent.status within 30s"
  fi

  echo "Step Security Job Correlation ID: ${correlation_id}"
  echo "Insights: ${WEB_URL}/github/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
  rm -rf "$work"
}

stop() {
  if [[ ! -d "$AGENT_DIR" ]]; then
    echo "no agent installed, nothing to stop"
    return 0
  fi
  if [[ -e "$AGENT_DIR/post_event.json" ]]; then
    echo "stop already ran"
    return 0
  fi

  echo '{"event":"post"}' > "$AGENT_DIR/post_event.json"
  for _ in $(seq 1 10); do
    [[ -f "$AGENT_DIR/done.json" ]] && break
    sleep 1
  done
  [[ -f "$AGENT_DIR/done.json" ]] || echo "timed out waiting for done.json"

  if [[ -f "$AGENT_DIR/agent.log" ]]; then
    echo "log:"
    cat "$AGENT_DIR/agent.log"
  fi
  if [[ -f "$AGENT_DIR/agent.status" ]]; then
    echo "status:"
    cat "$AGENT_DIR/agent.status"
    echo
  fi
}

case "${1:-}" in
  start) start "${2:-latest}" ;;
  stop) stop ;;
  *) fail "usage: install-int-agent.sh start [tag] | stop" ;;
esac
