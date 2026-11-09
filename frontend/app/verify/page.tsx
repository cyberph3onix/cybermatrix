"use client";

import { useState } from "react";
import { verifyById, verifyUploaded } from "@/lib/api";
import type { VerificationResult } from "@/lib/types";

function HashRow({ label, value, tone }: { label: string; value: string | null; tone?: string }) {
  return (
    <div>
      <dt className="text-sm text-muted">{label}</dt>
      <dd className={`mt-0.5 break-all font-mono text-xs sm:text-sm ${tone ?? ""}`}>
        {value ?? "Nothing registered on-chain for this report"}
      </dd>
    </div>
  );
}

export default function VerifyPage() {
  const [id, setId] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [res, setRes] = useState<VerificationResult | null>(null);
  const [source, setSource] = useState<string | null>(null);

  async function run(fn: () => Promise<VerificationResult>, label: string) {
    setBusy(true);
    setErr(null);
    setRes(null);
    try {
      setRes(await fn());
      setSource(label);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Verification failed. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function onFile(file: File | undefined) {
    if (!file) return;
    let json: unknown;
    try {
      json = JSON.parse(await file.text());
    } catch {
      setErr("This file isn't valid JSON. Upload the report.json you downloaded.");
      setRes(null);
      return;
    }
    run(() => verifyUploaded(json), `File: ${file.name}`);
  }

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="text-3xl font-semibold leading-tight">Verify a report</h1>
      <p className="mt-3 max-w-prose text-muted">
        We recompute the report&apos;s fingerprint and compare it with the one recorded on-chain.
        A match means the report hasn&apos;t changed since it was registered.
      </p>

      <form
        className="mt-8 space-y-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (id.trim()) run(() => verifyById(id.trim()), `Report ID: ${id.trim()}`);
        }}
      >
        <label htmlFor="rid" className="block font-medium">
          Report ID
        </label>
        <div className="flex flex-col gap-2 sm:flex-row">
          <input
            id="rid"
            value={id}
            onChange={(e) => setId(e.target.value)}
            placeholder="5f0c2a8e-6b1d-4c43-9a0e-2f3b7d9c1a11"
            className="min-h-11 w-full rounded-md border border-rule bg-panel px-3 font-mono text-sm"
            autoComplete="off"
            spellCheck={false}
          />
          <button
            type="submit"
            disabled={busy || !id.trim()}
            className="min-h-11 shrink-0 rounded bg-accent px-5 font-medium text-white hover:bg-[#163f64] disabled:opacity-50"
          >
            {busy ? "Verifying…" : "Verify"}
          </button>
        </div>
        <p className="text-sm text-muted">
          Try <button type="button" className="font-mono text-accent underline" onClick={() => setId("5f0c2a8e-6b1d-4c43-9a0e-2f3b7d9c1a11")}>5f0c2a8e…1a11</button>
        </p>
      </form>

      <div className="mt-6 border-t border-rule pt-6">
        <p className="font-medium">Or check a report file</p>
        <p className="mt-1 text-sm text-muted">
          The file is hashed in your browser. Edit it and verify again to see a mismatch.
        </p>
        <input
          id="file"
          type="file"
          accept="application/json,.json"
          className="sr-only"
          onChange={(e) => {
            onFile(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
        <label
          htmlFor="file"
          className="mt-3 inline-flex min-h-11 cursor-pointer items-center rounded border border-ink bg-panel px-4 text-sm font-medium hover:bg-paper has-[:focus-visible]:outline"
        >
          Upload report JSON
        </label>
      </div>

      <div aria-live="polite" className="mt-8">
        {err && (
          <p role="alert" className="rounded border border-c-mal bg-c-mal-tint p-3 text-sm text-c-mal-ink">
            {err}
          </p>
        )}
        {res && (
          <section
            aria-labelledby="result"
            className={`rounded-md border-2 ${res.match ? "border-c-low bg-c-low-tint" : "border-c-mal bg-c-mal-tint"}`}
          >
            <div className="p-4 sm:p-6">
              <h2 id="result" className={`text-2xl font-semibold ${res.match ? "text-c-low-ink" : "text-c-mal-ink"}`}>
                {res.match ? "MATCH" : "MISMATCH"}
              </h2>
              <p className="mt-1 text-sm">
                {res.match
                  ? "The report is identical to the version registered on-chain."
                  : res.onchain_hash
                    ? "This report differs from the version registered on-chain. It has been changed, or it is a different report."
                    : "No on-chain record exists for this report, so there is nothing to match."}
              </p>
              <p className="mt-1 text-xs text-muted">{source}</p>

              <dl className="mt-4 space-y-3 rounded bg-white/70 p-3">
                <HashRow label="Computed hash" value={res.computed_hash} />
                <HashRow label="On-chain hash" value={res.onchain_hash} />
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <dt className="text-muted">On-chain status</dt>
                    <dd className="font-medium">{res.onchain_status ?? "Not registered"}</dd>
                  </div>
                  <div>
                    <dt className="text-muted">Registered</dt>
                    <dd className="font-medium">
                      {res.onchain_created_at
                        ? new Date(res.onchain_created_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })
                        : "—"}
                    </dd>
                  </div>
                </div>
              </dl>

              {res.explorer_url && (
                <p className="mt-3 text-sm">
                  <a className="text-accent underline" href={res.explorer_url} target="_blank" rel="noopener noreferrer">
                    {res.tx_hash ? "View transaction on Etherscan (Sepolia)" : "View the registry contract on Etherscan (Sepolia)"}
                  </a>
                </p>
              )}
              <p className="mt-3 text-sm text-muted">{res.note}</p>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
