#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORT="${2:-80}"
PATH_VALUE="${3:-/}"
REPEAT="${4:-3}"

BASE_URL="http://${TARGET}:${PORT}${PATH_VALUE}"
PAYLOADS=(
  "?cmd=cat+/etc/passwd"
  "?q=union+select+1,2,3"
  "?file=../../../../etc/passwd"
)

echo "DASRS demo traffic sender"
echo "Target: ${BASE_URL}"
echo "Repeat: ${REPEAT}"
echo

for ((i=0; i<REPEAT; i++)); do
  for suffix in "${PAYLOADS[@]}"; do
    url="${BASE_URL}${suffix}"
    echo "[$(date +%H:%M:%S)] GET ${url}"
    code="$(curl -sS -o /dev/null -w '%{http_code}' "${url}" || true)"
    echo "  -> HTTP ${code}"
    sleep 1
  done
done

echo
echo "Done. Now check:"
echo "1. Suricata eve.json"
echo "2. DASRS alert list"
echo "3. Alert audit modal for Traffic Context and AI analysis"

