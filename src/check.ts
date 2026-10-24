import "dotenv/config";
import { createPublicClient, getAddress, http, type Address, type Chain } from "viem";
import { arbitrum, base, bsc, mainnet, optimism, polygon } from "viem/chains";

/**
 * MEV DAO Multi-Chain EIP-7702 Delegation Scanner
 * Full Technical Guide:
 * https://mevdao.org/blog/how-to-check-and-remove-a-malicious-eip-7702-delegation
 *
 * EIP-7702 Specification:
 * An EOA with an active delegation stores a 23-byte delegation designator in its code slot:
 *   0xef0100 || <20-byte implementation contract address> (48 hex chars total including 0x)
 */

export const SUPPORTED_CHAINS: Array<{ chain: Chain; rpcUrl: string }> = [
  { chain: mainnet, rpcUrl: process.env.ETH_RPC_URL || "https://eth.llamarpc.com" },
  { chain: base, rpcUrl: process.env.BASE_RPC_URL || "https://mainnet.base.org" },
  { chain: arbitrum, rpcUrl: process.env.ARBITRUM_RPC_URL || "https://arb1.arbitrum.io/rpc" },
  { chain: optimism, rpcUrl: process.env.OPTIMISM_RPC_URL || "https://mainnet.optimism.io" },
  { chain: polygon, rpcUrl: process.env.POLYGON_RPC_URL || "https://polygon-rpc.com" },
  { chain: bsc, rpcUrl: process.env.BSC_RPC_URL || "https://bsc-dataseed.binance.org" },
];

export const KNOWN_SAFE_IMPLEMENTATIONS: Record<string, string> = {
  "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b": "MetaMask DeleGator Smart Account",
  "0x0000000071727de22e5e9d8baf0edac6f37da032": "ERC-4337 EntryPoint v0.7",
  "0x4337084d9e255ff0702461cf8895ce9e3b5ff108": "ERC-4337 EntryPoint v0.8 (EIP-7702)",
};

export interface DelegationCheckResult {
  chainId: number;
  chainName: string;
  eoa: Address;
  status: "CLEAN_EOA" | "EIP7702_DELEGATED" | "SMART_CONTRACT" | "RPC_ERROR";
  delegatedTo?: Address;
  knownLabel?: string;
  rawBytecode?: string;
}

/**
 * Parses raw `eth_getCode` output and extracts the 20-byte EIP-7702 target if prefixed with `0xef0100`.
 */
export function parseEip7702Bytecode(bytecode: string | undefined): {
  isDelegated: boolean;
  delegatedAddress?: Address;
} {
  if (!bytecode || bytecode === "0x") {
    return { isDelegated: false };
  }
  const normalized = bytecode.toLowerCase();
  if (normalized.startsWith("0xef0100") && normalized.length === 48) {
    const rawTarget = `0x${normalized.slice(8)}`;
    return {
      isDelegated: true,
      delegatedAddress: getAddress(rawTarget),
    };
  }
  return { isDelegated: false };
}

export async function scanAddressAcrossChains(targetAddress: Address): Promise<DelegationCheckResult[]> {
  const tasks = SUPPORTED_CHAINS.map(async ({ chain, rpcUrl }): Promise<DelegationCheckResult> => {
    try {
      const client = createPublicClient({
        chain,
        transport: http(rpcUrl, { timeout: 8_000 }),
      });
      const bytecode = await client.getCode({ address: targetAddress });

      if (!bytecode || bytecode === "0x") {
        return {
          chainId: chain.id,
          chainName: chain.name,
          eoa: targetAddress,
          status: "CLEAN_EOA",
        };
      }

      const parsed = parseEip7702Bytecode(bytecode);
      if (parsed.isDelegated && parsed.delegatedAddress) {
        const label =
          KNOWN_SAFE_IMPLEMENTATIONS[parsed.delegatedAddress.toLowerCase()] ||
          "UNKNOWN / POTENTIAL MALICIOUS SWEEPER";
        return {
          chainId: chain.id,
          chainName: chain.name,
          eoa: targetAddress,
          status: "EIP7702_DELEGATED",
          delegatedTo: parsed.delegatedAddress,
          knownLabel: label,
          rawBytecode: bytecode,
        };
      }

      return {
        chainId: chain.id,
        chainName: chain.name,
        eoa: targetAddress,
        status: "SMART_CONTRACT",
        rawBytecode: `${bytecode.slice(0, 26)}...`,
      };
    } catch (err) {
      return {
        chainId: chain.id,
        chainName: chain.name,
        eoa: targetAddress,
        status: "RPC_ERROR",
        knownLabel: (err as Error).message.slice(0, 60),
      };
    }
  });

  return Promise.all(tasks);
}

async function main() {
  const cliTarget = process.argv[2] || process.env.TARGET_EOA_ADDRESS || "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
  const targetAddress = getAddress(cliTarget);

  console.log("=========================================================================");
  console.log("  MEV DAO EIP-7702 Multi-Chain Delegation Scanner (https://mevdao.org)");
  console.log("=========================================================================");
  console.log(`Inspecting Address: ${targetAddress}\n`);

  const results = await scanAddressAcrossChains(targetAddress);
  console.table(
    results.map((r) => ({
      Chain: `${r.chainName} (${r.chainId})`,
      Status: r.status,
      DelegatedTo: r.delegatedTo || "-",
      Classification: r.knownLabel || "Standard EOA (0x)",
    }))
  );

  const infected = results.filter((r) => r.status === "EIP7702_DELEGATED");
  if (infected.length > 0) {
    console.log(
      `\n[WARNING] Detected ${infected.length} active EIP-7702 delegation(s)! Run 'npm run revoke' or follow:`
    );
    console.log("https://mevdao.org/blog/how-to-check-and-remove-a-malicious-eip-7702-delegation");
  } else {
    console.log("\n[OK] No EIP-7702 (0xef0100) delegations detected across scanned networks.");
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
  });
}
