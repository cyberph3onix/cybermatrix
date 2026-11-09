/**
 * Minimal EIP-1193 wallet calls (MetaMask and compatible), no library.
 * Used for actions that must come from the user's own address, never the CyberMatrix relayer: a bonded dispute,
 * an EIP-712 signature vouching for a report (provenance), and a validator's setStatus.
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

async function account(chainId: number): Promise<{ eth: Eip1193; from: string }> {
  const eth = provider();
  if (!eth) throw new Error("No browser wallet found. Install MetaMask (or similar).");
  const [from] = (await eth.request({ method: "eth_requestAccounts" })) as string[];
  if (!from) throw new Error("The wallet didn't share an account.");
  const chain = hex(chainId);
  if ((await eth.request({ method: "eth_chainId" })) !== chain) {
    try {
      await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chain }] });
    } catch {
      throw new Error(`Switch your wallet to the network with chain ID ${chainId} (Sepolia) and try again.`);
    }
  }
  return { eth, from };
}

/** eth_signTypedData_v4 over the server-provided EIP-712 data. Returns { signer, signature }. */
export async function signTypedData(data: Record<string, unknown>): Promise<{ signer: string; signature: string }> {
  const domain = data.domain as { chainId: number };
  const { eth, from } = await account(Number(domain.chainId));
  const signature = (await eth.request({ method: "eth_signTypedData_v4", params: [from, JSON.stringify(data)] })) as string;
  return { signer: from, signature };
}

const word = (n: number | bigint) => BigInt(n).toString(16).padStart(64, "0");
const IS_VALIDATOR = "0xfacd743b"; // isValidator(address)
const SET_STATUS = "0xd896dd64"; // setStatus(uint256,uint8)
export const STATUS_INDEX = { validated: 2, rejected: 3 } as const; // ThreatRegistry.Status

/** Connects the wallet and reports whether its address holds the validator role on `contract`. */
export async function connectedValidator(chainId: number, contract: string): Promise<{ address: string; isValidator: boolean }> {
  const { eth, from } = await account(chainId);
  const out = (await eth.request({
    method: "eth_call",
    params: [{ to: contract, data: IS_VALIDATOR + word(BigInt(from)) }, "latest"],
  })) as string;
  return { address: from, isValidator: BigInt(out || "0x0") === BigInt(1) };
}

/** Validator only: setStatus(onchainId, Validated | Rejected) from the connected wallet. Returns the tx hash. */
export async function sendSetStatus(
  chainId: number, contract: string, onchainId: number, status: keyof typeof STATUS_INDEX,
): Promise<string> {
  const { eth, from } = await account(chainId);
  return (await eth.request({
    method: "eth_sendTransaction",
    params: [{ from, to: contract, data: SET_STATUS + word(onchainId) + word(STATUS_INDEX[status]) }],
  })) as string;
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
