#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DATA_DIR="${GMC_DESKTOP_DATA_DIR:-./meritora-desktop-data}"
ADDR="${GMC_DESKTOP_ADDR:-127.0.0.1:8787}"
URL="http://${ADDR}"

echo "Starting Meritora Desktop (Preview v0.2) at ${URL} ..."
echo "Data directory: ${DATA_DIR}"

(
  for _ in $(seq 1 60); do
    if command -v curl >/dev/null 2>&1 && curl -fsS "${URL}/health" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  if command -v open >/dev/null 2>&1; then
    open "${URL}" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${URL}" >/dev/null 2>&1 || true
  fi
) &

exec cargo run -p gmc-node -- workbench --data-dir "${DATA_DIR}" --addr "${ADDR}"
