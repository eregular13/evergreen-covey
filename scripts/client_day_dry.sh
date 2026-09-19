#!/usr/bin/env bash
# SAMPLE client-day dry: sign (lab HMAC) → ready --strict-e2e → plan (no spawn).
# Optional pack_drop from committed fixtures. SAMPLE ≠ client. No live scan.
# LICENSE-LOCK: never apt-install, never vendor Nmap / masscan / etc.
# From a clean checkout: ./scripts/client_day_dry.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Prefer the repo venv when present. Never apt-get. Never pip-install scanners.
if [[ -n "${PYTHON:-}" ]]; then
  PY="$PYTHON"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="python3"
fi

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

usage() {
  cat <<'EOF'
usage: scripts/client_day_dry.sh [--scope FILE] [--work DIR] [--export-from DIR] [--no-export]

One command DESKTOP/client-host dry (no live client scan):
  sign (demo/lab HMAC only) → ready --strict-e2e → plan (no spawn)
  then pack_drop from SAMPLE fixtures if a full assess would need BYO.

Missing BYO fails closed (printed miss list). Never apt-installs scanners.
masscan / arp-scan / netdiscover / zmap stay argv+unit only — ready --strict-e2e refuses them.
SAMPLE ≠ client. No RiskReady. No CTA.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

exec "$PY" -m covey client-day-dry "$@"
