#!/usr/bin/env bash
# Read-only checks for a wallet after a drainer: EIP-7702 delegation, ERC-20 allowance,
# Permit2 allowance and NFT operator approval. Needs Foundry's `cast`. Sends nothing.
#
# usage:
#   RPC=https://eth.llamarpc.com ./post-drainer-check.sh <wallet> [token] [spender] [nft] [operator]
set -euo pipefail
: "${RPC:?set RPC to an RPC URL}"
W=${1:?wallet address}; TOKEN=${2:-}; SPENDER=${3:-}; NFT=${4:-}; OP=${5:-}
PERMIT2=0x000000000022D473030F116dDEE9F6B43aC78BA3

# 1. EIP-7702: a delegated EOA has code 0xef0100 || <20-byte delegate address>
code=$(cast code "$W" --rpc-url "$RPC")
if [[ "$code" == 0xef0100* ]]; then
  echo "[!] EIP-7702 delegation active -> 0x${code:8:40}"
  echo "    Revoking token approvals won't help until this is cleared."
elif [[ "$code" == "0x" ]]; then
  echo "[ok] no code at $W (plain EOA, no 7702 delegation)"
else
  echo "[i] $W is a contract (code length $(( (${#code}-2)/2 )) bytes)"
fi

# 2. Plain ERC-20 allowance
if [[ -n "$TOKEN" && -n "$SPENDER" ]]; then
  a=$(cast call "$TOKEN" "allowance(address,address)(uint256)" "$W" "$SPENDER" --rpc-url "$RPC")
  echo "[i] ERC-20 allowance to $SPENDER: $a"
  # 3. Permit2 allowance: (uint160 amount, uint48 expiration, uint48 nonce)
  p=$(cast call "$PERMIT2" "allowance(address,address,address)(uint160,uint48,uint48)" "$W" "$TOKEN" "$SPENDER" --rpc-url "$RPC" | tr '\n' ' ')
  echo "[i] Permit2 allowance (amount expiration nonce): $p"
  echo "    A token can show 0 above and still be open through Permit2 if the Permit2 contract itself is approved."
  pa=$(cast call "$TOKEN" "allowance(address,address)(uint256)" "$W" "$PERMIT2" --rpc-url "$RPC")
  echo "[i] ERC-20 allowance to Permit2: $pa"
fi

# 4. NFT operator approval (setApprovalForAll)
if [[ -n "$NFT" && -n "$OP" ]]; then
  b=$(cast call "$NFT" "isApprovedForAll(address,address)(bool)" "$W" "$OP" --rpc-url "$RPC")
  echo "[i] isApprovedForAll($OP) on $NFT: $b"
fi

# 5. If the key itself leaked, every revoke needs gas the sweeper can take.
bal=$(cast balance "$W" --ether --rpc-url "$RPC")
echo "[i] ETH balance: $bal"
echo "If the drain was signed by your own key, stop funding this address and move what's left in one bundle."
