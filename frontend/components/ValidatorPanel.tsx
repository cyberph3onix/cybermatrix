"use client";

import { useState } from "react";
import { connectedValidator, sendSetStatus } from "@/lib/wallet";

/** Validators only: set Validated / Rejected from the validator's own wallet. The contract enforces the role. */
export function ValidatorPanel({
  chainId, contract, onchainId, onSent,
}: { chainId: number; contract: string; onchainId: number; onSent: () => void }) {
  const [who, setWho] = useState<{ address: string; isValidator: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function connect() {
    setMsg(null);
    try {
      setWho(await connectedValidator(chainId, contract));
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Couldn't connect the wallet.");
    }
  }

  async function set(status: "validated" | "rejected") {
    setBusy(true);
    setMsg(null);
    try {
      const tx = await sendSetStatus(chainId, contract, onchainId, status);
      setMsg(`Sent ${status} (transaction ${tx.slice(0, 12)}…). The status updates once it is mined.`);
      setTimeout(onSent, 15_000);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "The transaction wasn't sent.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <details className="mt-4 rounded border border-rule p-3 text-sm">
      <summary className="cursor-pointer font-medium">Validator review</summary>
      <p className="mt-2 text-muted">
        Validators are addresses the registry owner appointed. A validator&apos;s decision records their judgement; it
        is our own key&apos;s authority, not an outside one. Resolving a dispute returns or keeps the bond.
      </p>
      {!who && (
        <button type="button" onClick={connect} className="mt-2 min-h-11 rounded border border-rule px-4 py-2 font-medium hover:bg-panel">
          Connect validator wallet
        </button>
      )}
      {who && !who.isValidator && (
        <p className="mt-2 break-all">{who.address} is not a validator on this registry.</p>
      )}
      {who?.isValidator && (
        <div className="mt-2 flex flex-wrap gap-2">
          <button type="button" disabled={busy} onClick={() => set("validated")}
            className="min-h-11 rounded border border-c-low px-4 py-2 font-medium text-c-low-ink disabled:opacity-60">
            Mark validated
          </button>
          <button type="button" disabled={busy} onClick={() => set("rejected")}
            className="min-h-11 rounded border border-c-mal px-4 py-2 font-medium text-c-mal-ink disabled:opacity-60">
            Mark rejected
          </button>
        </div>
      )}
      {msg && <p className="mt-2" role="status">{msg}</p>}
    </details>
  );
}
