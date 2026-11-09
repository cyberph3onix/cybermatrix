"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getRegistration, registerReport } from "@/lib/api";
import type { RegistryRecord } from "@/lib/types";
import { RegistryHistory } from "./RegistryHistory";

export function RegisterButton({ reportId }: { reportId: string }) {
  const [rec, setRec] = useState<RegistryRecord | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getRegistration(reportId).then(setRec).catch(() => {});
  }, [reportId]);

  async function go() {
    setBusy(true);
    setErr(null);
    try {
      setRec(await registerReport(reportId));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Registration failed. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-md border border-rule bg-panel p-4">
      <p className="max-w-prose text-sm">
        Registering saves a fingerprint of this report on the Sepolia test network so anyone can
        later check it hasn&apos;t been altered. Only the fingerprint, status and time go on-chain,
        submitted from this service&apos;s shared relayer address (not a wallet of yours). The link,
        message and personal details stay off-chain.
      </p>

      {rec ? (
        <div role="status" className="mt-3 text-sm">
          <p className="font-medium">Registered on-chain (status: {rec.status}).</p>
          <p className="mt-1 break-all font-mono text-xs">{rec.report_hash}</p>
          <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            {rec.tx_hash && (
              <a
                className="text-accent underline"
                href={`https://sepolia.etherscan.io/tx/${rec.tx_hash}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                View transaction on Etherscan
              </a>
            )}
            <Link className="text-accent underline" href="/verify">
              Verify this report
            </Link>
          </p>
          <RegistryHistory reportId={reportId} refreshKey={rec.onchain_id ?? 0} />
        </div>
      ) : (
        <button
          type="button"
          onClick={go}
          disabled={busy}
          className="mt-3 min-h-11 rounded bg-accent px-4 py-2 text-sm font-medium text-white hover:bg-[#163f64] disabled:opacity-60"
        >
          {busy ? "Registering…" : "Register on-chain"}
        </button>
      )}
      {err && (
        <p role="alert" className="mt-3 text-sm text-c-mal-ink">
          {err}
        </p>
      )}
    </div>
  );
}
