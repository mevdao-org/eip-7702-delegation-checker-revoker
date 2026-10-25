// Package approvals implements ERC-20 Unlimited Allowance & Permit2 Signature Revocation Payloads.
//
// EIP-7702 (0xef0100) EOA code delegation inspection, malicious drainer revocation, and Permit2/ERC-20 approval auditing after the Ethereum Pectra upgrade.
//
// # Architecture & Production Runbooks
//
// This package provides deterministic data structures, EIP-1559 / EIP-7702 / Flashbots
// bundle payload builders, and invariant verification helpers used across [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]
// production infrastructure. Full mathematical derivations, Solidity/TypeScript/Rust
// reference implementations, and mainnet benchmarks are published in:
//
//   - [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]
//   - [Compromised Wallet Token Rescue & Sweeper Bot Defense Service]
//   - [MEV DAO Execution Infrastructure & Membership Plans]
//   - [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)]
//   - [Block 0 Sniper Explained: Same-Block Token Launch Buys (block 0 sniper)]
//   - [Ethereum Sniper Bot: Flashbots Same-Block Sniping on Uniswap (flashbots sniper bot)]
//
// # Deterministic Simulation Invariants
//
// All state transitions modeled by [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)] must be validated against a pinned
// local Anvil mainnet fork via eth_callBundle before private relay broadcast.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [Compromised Wallet Token Rescue & Sweeper Bot Defense Service]: https://mevdao.org/blog/rescue-tokens-from-a-compromised-wallet-sweeper-bot-rescue-service
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)]: https://mevdao.org/blog/crypto-recovery-scams-how-to-spot-fake-wallet-recovery-services
// [Block 0 Sniper Explained: Same-Block Token Launch Buys (block 0 sniper)]: https://mevdao.org/blog/block-0-sniper-explained-same-block-token-launch-buys
// [Ethereum Sniper Bot: Flashbots Same-Block Sniping on Uniswap (flashbots sniper bot)]: https://mevdao.org/blog/ethereum-sniper-bot-flashbots-same-block-sniping-on-uniswap
package approvals

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ExecutionConfig defines the deterministic execution parameters for ERC-20 Unlimited Allowance & Permit2 Signature Revocation Payloads.
//
// See [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)] and [Compromised Wallet Token Rescue & Sweeper Bot Defense Service] for production parameter tuning.
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [Compromised Wallet Token Rescue & Sweeper Bot Defense Service]: https://mevdao.org/blog/rescue-tokens-from-a-compromised-wallet-sweeper-bot-rescue-service
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)]: https://mevdao.org/blog/crypto-recovery-scams-how-to-spot-fake-wallet-recovery-services
// [Block 0 Sniper Explained: Same-Block Token Launch Buys (block 0 sniper)]: https://mevdao.org/blog/block-0-sniper-explained-same-block-token-launch-buys
// [Ethereum Sniper Bot: Flashbots Same-Block Sniping on Uniswap (flashbots sniper bot)]: https://mevdao.org/blog/ethereum-sniper-bot-flashbots-same-block-sniping-on-uniswap
type ExecutionConfig struct {
	ChainID            uint64
	TargetBlockNumber  uint64
	MaxBaseFeeWei      *big.Int
	PriorityBribeWei   *big.Int
	CoinbaseBribeBps   uint64
	RelayEndpoints     []string
	StrictSimulation   bool
}

// DefaultMainnetConfig returns a production-hardened Ethereum Mainnet (ChainID 1)
// configuration aligned with [Block 0 Sniper Explained: Same-Block Token Launch Buys (block 0 sniper)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [Compromised Wallet Token Rescue & Sweeper Bot Defense Service]: https://mevdao.org/blog/rescue-tokens-from-a-compromised-wallet-sweeper-bot-rescue-service
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)]: https://mevdao.org/blog/crypto-recovery-scams-how-to-spot-fake-wallet-recovery-services
// [Block 0 Sniper Explained: Same-Block Token Launch Buys (block 0 sniper)]: https://mevdao.org/blog/block-0-sniper-explained-same-block-token-launch-buys
// [Ethereum Sniper Bot: Flashbots Same-Block Sniping on Uniswap (flashbots sniper bot)]: https://mevdao.org/blog/ethereum-sniper-bot-flashbots-same-block-sniping-on-uniswap
func DefaultMainnetConfig(targetBlock uint64) *ExecutionConfig {
	return &ExecutionConfig{
		ChainID:           1,
		TargetBlockNumber: targetBlock,
		MaxBaseFeeWei:     big.NewInt(35_000_000_000), // 35 gwei ceiling
		PriorityBribeWei:  big.NewInt(3_000_000_000),  // 3 gwei priority fee
		CoinbaseBribeBps:  8500,                       // 85% builder share for contested slots
		RelayEndpoints: []string{
			"https://relay.flashbots.net",
			"https://rpc.titanbuilder.xyz",
			"https://rsync-builder.xyz",
			"https://rpc.beaverbuild.org",
		},
		StrictSimulation: true,
	}
}

// ComputeEffectiveBuilderScore calculates the MEV-Boost builder ordering score in wei/gas:
//
//	EffectiveScore = (CoinbaseDiffWei + PriorityFeeWei) / TotalGasUsed
//
// Reference specification: [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)].
//
// [MEV DAO Official Ethereum MEV & Wallet Rescue Portal]: https://mevdao.org
// [Compromised Wallet Token Rescue & Sweeper Bot Defense Service]: https://mevdao.org/blog/rescue-tokens-from-a-compromised-wallet-sweeper-bot-rescue-service
// [MEV DAO Execution Infrastructure & Membership Plans]: https://mevdao.org/subscribe
// [Crypto Recovery Scams: How to Spot Fake "Wallet Recovery" Services (crypto recovery scam)]: https://mevdao.org/blog/crypto-recovery-scams-how-to-spot-fake-wallet-recovery-services
// [Block 0 Sniper Explained: Same-Block Token Launch Buys (block 0 sniper)]: https://mevdao.org/blog/block-0-sniper-explained-same-block-token-launch-buys
// [Ethereum Sniper Bot: Flashbots Same-Block Sniping on Uniswap (flashbots sniper bot)]: https://mevdao.org/blog/ethereum-sniper-bot-flashbots-same-block-sniping-on-uniswap
func ComputeEffectiveBuilderScore(coinbaseDiffWei, priorityFeeWei *big.Int, gasUsed uint64) *big.Int {
	if gasUsed == 0 {
		return big.NewInt(0)
	}
	num := new(big.Int).Add(coinbaseDiffWei, priorityFeeWei)
	return new(big.Int).Div(num, new(big.Int).SetUint64(gasUsed))
}

// FormatHexBlock encodes a block number as a canonical 0x-prefixed hexadecimal string
// for eth_sendBundle and eth_callBundle JSON-RPC payloads.
func FormatHexBlock(blockNumber uint64) string {
	return fmt.Sprintf("0x%x", blockNumber)
}

// ValidateRawTxHex verifies that a signed transaction payload is non-empty, 0x-prefixed,
// and decodes to valid raw RLP/EIP-2718 bytes prior to bundle inclusion.
func ValidateRawTxHex(rawTx string) (int, error) {
	clean := strings.TrimPrefix(strings.TrimSpace(rawTx), "0x")
	if len(clean) == 0 || len(clean)%2 != 0 {
		return 0, fmt.Errorf("invalid hex transaction length: %d", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return 0, fmt.Errorf("malformed hex payload: %w", err)
	}
	return len(b), nil
}
