"use client";

import { useState } from "react";
import { campaignUrl, registerCampaign } from "@/lib/api";
import type { CampaignRecord } from "@/lib/types";

/** Freeze a cluster as a campaign manifest and commit its hash to the registry (relayer pays gas). */
export function CampaignButton({ clusterId }: { clusterId: string }) {
  const [rec, setRec] = useState<CampaignRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    setBusy(true);
    setErr(null);
    try {
      setRec(await registerCampaign(clusterId));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Registration failed.");
    } finally {
      setBusy(false);
    }
  }

  if (rec) {
    return (
      <p className="mt-3 break-all text-sm" role="status">
        Campaign registered (on-chain #{rec.onchain_id}).{" "}
        <a className="text-accent underline" href={campaignUrl(rec.campaign_id)}
          target="_blank" rel="noopener noreferrer">Manifest</a>
        {rec.explorer_url && (
          <>
            {" · "}
            <a className="text-accent underline" href={rec.explorer_url} target="_blank" rel="noopener noreferrer">Transaction</a>
          </>
        )}
        . Upload the manifest on the Verify page to check it.
      </p>
    );
  }
  return (
    <div className="mt-3">
      <button type="button" onClick={go} disabled={busy}
        className="min-h-11 rounded border border-accent px-4 py-2 text-sm font-medium text-accent hover:bg-panel disabled:opacity-60">
        {busy ? "Registering (waiting for the transaction)…" : "Register this campaign on-chain"}
      </button>
      <p className="mt-1 text-xs text-muted">Commits a hash of the member report hashes, shared indicators and links. No message text.</p>
      {err && <p className="mt-1 text-sm text-c-mal-ink" role="alert">{err}</p>}
    </div>
  );
}
