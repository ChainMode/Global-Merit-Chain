#!/usr/bin/env bash
# GMChain One-Command Public Testnet & Live HTTP RPC / Explorer Launcher
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DATA_DIR="${GMC_TESTNET_DATA_DIR:-./testnet-data}"
ADDR="${GMC_TESTNET_ADDR:-127.0.0.1:8546}"
CHAIN_ID="${GMC_TESTNET_CHAIN_ID:-gmchain-public-testnet-1}"
URL="http://${ADDR}"

echo "========================================================================"
echo "  GMChain (Global Merit Chain / 公誉链) Public Testnet Kit"
echo "  Chain ID      : ${CHAIN_ID}"
echo "  Data Dir      : ${DATA_DIR}"
echo "  JSON-RPC 2.0  : ${URL}/rpc"
echo "  Explorer API  : ${URL}/api/explorer"
echo "  Bounties API  : ${URL}/api/bounties"
echo "  Proposals API : ${URL}/api/proposals"
echo "  Invariants    : FEE = 0 μ | BLOCK_REWARD = 0 μ | VALIDATOR_REWARD = 0 μ"
echo "========================================================================"

exec cargo run -p gmc-node -- testnet \
  --data-dir "${DATA_DIR}" \
  --chain-id "${CHAIN_ID}" \
  --addr "${ADDR}" \
  "$@"
