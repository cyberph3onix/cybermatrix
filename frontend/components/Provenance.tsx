"use client";

import { useEffect, useState } from "react";
import { addAttestation, getAttestations, getEvidenceManifest } from "@/lib/api";
import type { Attestations, EvidenceManifest } from "@/lib/types";
import { hasWallet, signTypedData } from "@/lib/wallet";

/** Report fingerprint, per-evidence hashes, and optional EIP-712 signatures from users' own wallets. */
export function Provenance({ reportId }: { reportId: string }) {
  const [m, setM] = useState<EvidenceManifest | null>(null);
  const [a, setA] = useState<Attestations | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getEvidenceManifest(reportId).then(setM).catch(() => undefined);
    getAttestations(reportId).then(setA).catch(() => undefined); // 503 when no registry is configured
  }, [reportId]);

  async function sign() {
    if (!a) return;
    setBusy(true);
    setMsg(null);
    try {
      const { signer, signature } = await signTypedData(a.typed_data);
      setA(await addAttestation(reportId, signer, signature));
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "The signature wasn't added.");
    } finally {
      setBusy(false);
    }
  }

  if (!m) return null;
  return (
    <div className="space-y-4 text-sm">
      <p>
        Report fingerprint (keccak256, the value committed on-chain):{" "}
        <code className="break-all font-mono text-xs">{m.report_hash}</code>
      </p>
      <details>
        <summary className="cursor-pointer font-medium">Evidence references ({m.evidence.length})</summary>
        <ul className="mt-2 space-y-1">
          {m.evidence.map((e) => (
            <li key={`${e.check_id}-${e.index}`} className="break-all">
              <span className="font-mono text-xs">{e.check_id}</span> · {e.kind} from {e.source}:{" "}
              <code className="font-mono text-xs text-muted">{e.sha256}</code>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-muted">{m.note}</p>
      </details>
      {a && (
        <div>
          <p className="font-medium">Vouched for by</p>
          {a.attestations.length === 0 ? (
            <p className="text-muted">No wallet has signed this report yet.</p>
          ) : (
            <ul className="mt-1 space-y-1">
              {a.attestations.map((x) => (
                <li key={x.signer} className="break-all font-mono text-xs">{x.signer}</li>
              ))}
            </ul>
          )}
          {hasWallet() && (
            <button type="button" onClick={sign} disabled={busy}
              className="mt-2 min-h-11 rounded border border-rule px-4 py-2 font-medium hover:bg-panel disabled:opacity-60">
              {busy ? "Waiting for your wallet…" : "Sign as a reporter with my wallet (free, no transaction)"}
            </button>
          )}
          <p className="mt-2 text-xs text-muted">{a.note}</p>
          {msg && <p className="mt-1 text-c-mal-ink" role="alert">{msg}</p>}
        </div>
      )}
    </div>
  );
}
