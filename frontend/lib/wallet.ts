/**
 * Minimal EIP-1193 wallet calls (MetaMask and compatible), no library.
 * Used only to send a bonded dispute from the user's own address: the CyberMatrix relayer never disputes.
 */
import type { DisputePrepared } from "./types";

type Eip1193 = { request(args: { method: string; params?: unknown[] }): Promise<unknown> };

function provider(): Eip1193 | null {
  if (typeof window === "undefined") return null;
  return ((window as unknown as { ethereum?: Eip1193 }).ethereum ?? null);
}

export const hasWallet = () => provider() !== null;

const hex = (n: number | bigint) => "0x" + BigInt(n).toString(16);

/** wei → "0.001" ETH, without floats. */
export function formatEth(wei: number | bigint): string {
  const w = BigInt(wei);
  const unit = BigInt("1000000000000000000"); // 1e18 (BigInt literals need ES2020; tsconfig targets ES2017)
  const whole = w / unit;
  const frac = (w % unit).toString().padStart(18, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}

/** Ask the wallet to send disputeReport(onchain_id, reason_hash) with value = bond. Returns the tx hash. */
export async function sendDispute(p: DisputePrepared): Promise<string> {
  const eth = provider();
  if (!eth) throw new Error("No browser wallet found. Install MetaMask (or similar) to dispute a report.");
  const [from] = (await eth.request({ method: "eth_requestAccounts" })) as string[];
  if (!from) throw new Error("The wallet didn't share an account.");
  const chain = hex(p.chain_id);
  if ((await eth.request({ method: "eth_chainId" })) !== chain) {
    try {
      await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chain }] });
    } catch {
      throw new Error(`Switch your wallet to the network with chain ID ${p.chain_id} (Sepolia) and try again.`);
    }
  }
  return (await eth.request({
    method: "eth_sendTransaction",
    params: [{ from, to: p.contract_address, data: p.calldata, value: hex(p.bond_wei) }],
  })) as string;
}
