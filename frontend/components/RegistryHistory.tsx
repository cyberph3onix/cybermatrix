"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { getHistory, prepareDispute, reassessReport } from "@/lib/api";
import type { RegistryStatus, ReportHistory } from "@/lib/types";
import { formatEth, hasWallet, sendDispute } from "@/lib/wallet";

const STATUS_TEXT: Record<RegistryStatus, string> = {
  submitted: "Submitted: registered, not yet reviewed",
  validated: "Validated by a reviewer",
  disputed: "Disputed: waiting for a reviewer",
  rejected: "Rejected by a reviewer",
  superseded: "Superseded by a newer version",
};

const STATUS_DOT: Record<RegistryStatus, string> = {
  submitted: "bg-c-inc",
  validated: "bg-c-low",
  disputed: "bg-c-susp",
  rejected: "bg-c-mal",
  superseded: "bg-rule",
};

export function RegistryHistory({ reportId, refreshKey = 0 }: { reportId: string; refreshKey?: number }) {
  const router = useRouter();
  const [h, setH] = useState<ReportHistory | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"reassess" | "dispute" | null>(null);
  const [showDispute, setShowDispute] = useState(false);
  const [reason, setReason] = useState("");
  const [sent, setSent] = useState<string | null>(null);

  const load = useCallback(() => {
    getHistory(reportId)
      .then(setH)
      .catch((e) => setErr(e instanceof Error ? e.message : "Couldn't load the registry history."));
  }, [reportId]);

  useEffect(load, [load, refreshKey]);

  async function reassess() {
    setBusy("reassess");
    setErr(null);
    try {
      const { report_id } = await reassessReport(reportId);
      router.push(`/report/${report_id}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Re-assessment failed.");
      setBusy(null);
    }
  }

  async function dispute() {
    setBusy("dispute");
    setErr(null);
    try {
      const prepared = await prepareDispute(reportId, reason);
      setSent(await sendDispute(prepared));
      setShowDispute(false);
      setTimeout(load, 15_000); // the status flips once the transaction is mined
    } catch (e) {
      setErr(e instanceof Error ? e.message : "The dispute wasn't sent.");
    } finally {
      setBusy(null);
    }
  }

  if (!h) {
    return err ? <p className="mt-3 text-sm text-muted">{err}</p> : null;
  }
  if (!h.registered) return null;

  return (
    <div className="mt-4 border-t border-rule pt-4">
      <h3 className="text-sm font-semibold">Version history</h3>
      <ol className="mt-2 space-y-2">
        {h.versions.map((v, i) => (
          <li key={v.report_hash} className="flex gap-3 text-sm">
            <span aria-hidden className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${STATUS_DOT[v.status]}`} />
            <div className="min-w-0">
              <p>
                <span className="font-medium">v{i + 1}</span>
                {v.is_current ? " (this report)" : ""}: {STATUS_TEXT[v.status]}
                {v.onchain_id != null && <span className="text-muted"> · on-chain #{v.onchain_id}</span>}
              </p>
              <p className="flex flex-wrap gap-x-3 text-xs">
                {v.report_id && !v.is_current && (
                  <Link className="text-accent underline" href={`/report/${v.report_id}`}>
                    Open this version
                  </Link>
                )}
                {v.explorer_url && (
                  <a className="text-accent underline" href={v.explorer_url} target="_blank" rel="noopener noreferrer">
                    Transaction
                  </a>
                )}
                <span className="break-all font-mono text-muted">{v.report_hash.slice(0, 18)}…</span>
              </p>
            </div>
          </li>
        ))}
      </ol>

      {h.open_dispute && (
        <div className="mt-3 rounded border border-c-susp bg-c-susp-tint p-3 text-sm text-c-susp-ink">
          <p className="font-medium">Open dispute ({formatEth(h.open_dispute.bond_wei)} ETH bond posted)</p>
          <p className="mt-1 break-all font-mono text-xs">by {h.open_dispute.disputer}</p>
          {h.open_dispute.reason && <p className="mt-1">“{h.open_dispute.reason}”</p>}
        </div>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        {h.can_reassess && (
          <button
            type="button"
            onClick={reassess}
            disabled={busy !== null}
            className="min-h-11 rounded border border-accent px-4 py-2 text-sm font-medium text-accent hover:bg-panel disabled:opacity-60"
          >
            {busy === "reassess" ? "Re-assessing and registering…" : "Re-assess and register a new version"}
          </button>
        )}
        {h.can_dispute && !showDispute && (
          <button
            type="button"
            onClick={() => setShowDispute(true)}
            disabled={busy !== null}
            className="min-h-11 rounded border border-rule px-4 py-2 text-sm font-medium hover:bg-panel disabled:opacity-60"
          >
            Dispute this report
          </button>
        )}
      </div>

      {showDispute && (
        <div className="mt-3 rounded border border-rule p-3">
          <label htmlFor="dispute-reason" className="text-sm font-medium">
            Why is this report wrong?
          </label>
          <textarea
            id="dispute-reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            maxLength={2000}
            className="mt-1 w-full rounded border border-rule bg-paper p-2 text-base"
          />
          <p className="mt-1 max-w-prose text-xs text-muted">
            Your wallet sends the dispute and posts a bond of{" "}
            <strong>{h.dispute_bond_wei != null ? formatEth(h.dispute_bond_wei) : "?"} Sepolia ETH</strong>. A
            reviewer decides: if they agree with you (Rejected), the bond is returned to you; if not (Validated), it
            is kept. The reason text stays on this server with personal details masked; only its hash goes on-chain.
          </p>
          {!hasWallet() && (
            <p className="mt-2 text-sm text-c-mal-ink">No browser wallet detected. Install MetaMask to dispute.</p>
          )}
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              onClick={dispute}
              disabled={busy !== null || reason.trim().length < 10 || !hasWallet()}
              className="min-h-11 rounded bg-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-60"
            >
              {busy === "dispute" ? "Waiting for your wallet…" : "Send dispute from my wallet"}
            </button>
            <button type="button" onClick={() => setShowDispute(false)} className="min-h-11 px-3 text-sm underline">
              Cancel
            </button>
          </div>
        </div>
      )}

      {sent && (
        <p role="status" className="mt-3 break-all text-sm">
          Dispute sent:{" "}
          <a className="text-accent underline" href={`https://sepolia.etherscan.io/tx/${sent}`} target="_blank" rel="noopener noreferrer">
            {sent.slice(0, 18)}…
          </a>
          . The status updates once it is mined.
        </p>
      )}
      {err && (
        <p role="alert" className="mt-3 text-sm text-c-mal-ink">
          {err}
        </p>
      )}
      <p className="mt-3 max-w-prose text-xs text-muted">{h.note}</p>
    </div>
  );
}
