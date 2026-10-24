import "dotenv/config";
import {
  createPublicClient,
  createWalletClient,
  http,
  zeroAddress,
  type Chain,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { arbitrum, base, bsc, mainnet, optimism, polygon } from "viem/chains";
import { parseEip7702Bytecode } from "./check.js";

/**
 * MEV DAO EIP-7702 Sponsored Type-4 (0x04) Zero-Address Revocation Tool
 * Full Technical Guide:
 * https://mevdao.org/blog/how-to-check-and-remove-a-malicious-eip-7702-delegation
 *
 * Why Sponsored Revocation Matters:
 * When a wallet is infected with a malicious EIP-7702 sweeper delegation (`0xef0100...`),
 * sending ETH to the infected wallet to pay for gas will trigger the attacker's malicious
 * `receive()` fallback hook and immediately forward the ETH to the attacker!
 *
 * Instead, EIP-7702 natively allows a SEPARATE clean wallet (`SPONSOR_PRIVATE_KEY`) to submit
 * and pay gas for the Type-4 (`0x04`) transaction while carrying the revocation authorization
 * tuple signed offline by `DELEGATED_EOA_PRIVATE_KEY` pointing to `0x0000000000000000000000000000000000000000`.
 */

const CHAINS_BY_ID: Record<number, Chain> = {
  1: mainnet,
  8453: base,
  42161: arbitrum,
  10: optimism,
  137: polygon,
  56: bsc,
};

async function main() {
  const chainId = Number(process.env.CHAIN_ID || "1");
  const chain = CHAINS_BY_ID[chainId] || mainnet;
  const rpcUrl = process.env.RPC_URL || "https://eth.llamarpc.com";

  const delegatedPk = process.env.DELEGATED_EOA_PRIVATE_KEY as Hex | undefined;
  const sponsorPk = (process.env.SPONSOR_PRIVATE_KEY || delegatedPk) as Hex | undefined;

  if (!delegatedPk || !sponsorPk) {
    console.log("=========================================================================");
    console.log("  MEV DAO EIP-7702 Type-4 Zero-Address Revocation CLI (https://mevdao.org)");
    console.log("=========================================================================");
    console.log(
      "Usage: Configure DELEGATED_EOA_PRIVATE_KEY and SPONSOR_PRIVATE_KEY in .env to broadcast a live Type-4 revocation."
    );
    console.log(
      "Guide: https://mevdao.org/blog/how-to-check-and-remove-a-malicious-eip-7702-delegation"
    );
    return;
  }

  const delegatedAccount = privateKeyToAccount(delegatedPk);
  const sponsorAccount = privateKeyToAccount(sponsorPk);

  const publicClient = createPublicClient({
    chain,
    transport: http(rpcUrl),
  });
  const sponsorWallet = createWalletClient({
    account: sponsorAccount,
    chain,
    transport: http(rpcUrl),
  });

  console.log("=========================================================================");
  console.log("  MEV DAO EIP-7702 Type-4 Zero-Address Revocation CLI (https://mevdao.org)");
  console.log("=========================================================================");
  console.log(`Target Chain            : ${chain.name} (chainId: ${chain.id})`);
  console.log(`Infected EOA (Revoking) : ${delegatedAccount.address}`);
  console.log(`Gas Sponsor Account     : ${sponsorAccount.address}`);

  const currentCode = await publicClient.getCode({ address: delegatedAccount.address });
  const parsed = parseEip7702Bytecode(currentCode);

  if (!parsed.isDelegated) {
    console.log(`\n[INFO] Address ${delegatedAccount.address} does not currently have a 0xef0100 delegation on ${chain.name}.`);
  } else {
    console.log(`\n[DETECTED] Active EIP-7702 delegation to: ${parsed.delegatedAddress}`);
  }

  // Step 1: Sign EIP-7702 authorization tuple delegating back to 0x0000000000000000000000000000000000000000
  const eoaNonce = await publicClient.getTransactionCount({ address: delegatedAccount.address });
  // If sponsor == delegatedAccount, the outer Type-4 tx increments the nonce before processing authorizationList
  const authNonce =
    sponsorAccount.address.toLowerCase() === delegatedAccount.address.toLowerCase()
      ? eoaNonce + 1
      : eoaNonce;

  const revocationAuth = await (sponsorWallet as any).signAuthorization({
    account: delegatedAccount,
    contractAddress: zeroAddress,
    chainId: chain.id,
    nonce: authNonce,
  });

  console.log("\n[SIGNED] EIP-7702 Zero-Address Revocation Authorization Tuple:");
  console.log(
    JSON.stringify(
      {
        chainId: revocationAuth.chainId,
        address: revocationAuth.address,
        nonce: Number(revocationAuth.nonce),
      },
      null,
      2
    )
  );

  // Step 2: Broadcast Type-4 (0x04) transaction paid by Sponsor Wallet
  const txHash = await (sponsorWallet as any).sendTransaction({
    account: sponsorAccount,
    to: delegatedAccount.address,
    value: 0n,
    authorizationList: [revocationAuth],
  });

  console.log(`\n[BROADCASTED] Type-4 Revocation Transaction Hash: ${txHash}`);
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  console.log(`[CONFIRMED] Mined in block #${receipt.blockNumber} (Status: ${receipt.status})`);

  const codeAfter = await publicClient.getCode({ address: delegatedAccount.address });
  console.log(`[VERIFIED] Post-revocation eth_getCode: ${codeAfter || "0x (Clean EOA restored!)"}`);
}

main().catch((err) => {
  console.error("Fatal error during EIP-7702 revocation:", err);
  process.exit(1);
});
