"use client";

import { useState } from "react";
import { ownershipChallenge, ownershipVerify } from "@/lib/api";
import type { OwnershipChallenge, OwnershipGrant } from "@/lib/types";

/** Prove you own a site before we check whether its /.env and /.git are readable. */
export function OwnershipPanel({
  target,
  grant,
  onGrant,
}: {
  target: string;
  grant: OwnershipGrant | null;
  onGrant: (g: OwnershipGrant | null) => void;
}) {
  const [ch, setCh] = useState<OwnershipChallenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function start() {
    setBusy(true);
    setErr(null);
    try {
      setCh(await ownershipChallenge(target));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't start verification.");
    } finally {
      setBusy(false);
    }
  }

  async function check() {
    if (!ch) return;
    setBusy(true);
    setErr(null);
    try {
      onGrant(await ownershipVerify(ch.challenge));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Not verified yet.");
    } finally {
      setBusy(false);
    }
  }

  if (grant) {
    return (
      <p role="status" className="rounded border border-c-low bg-c-low-tint p-3 text-sm text-c-low-ink">
        Ownership of <strong>{grant.domain}</strong> verified by {grant.method === "dns" ? "DNS record" : "file"}. The
        exposure check will run.{" "}
        <button type="button" className="underline" onClick={() => onGrant(null)}>
          Don&apos;t run it
        </button>
      </p>
    );
  }

  return (
    <div className="rounded border border-rule bg-panel p-3 text-sm">
      {!ch ? (
        <>
          <p className="text-muted">
            We only make these extra requests for sites whose owner has proved control of the domain.
          </p>
          <button
            type="button"
            onClick={start}
            disabled={busy || !target.trim()}
            className="mt-2 min-h-11 rounded border border-accent px-4 py-2 font-medium text-accent disabled:opacity-60"
          >
            {busy ? "Starting…" : "Prove I own this site"}
          </button>
        </>
      ) : (
        <>
          <p>
            Do <strong>one</strong> of these for <strong>{ch.domain}</strong>, then press Check:
          </p>
          <ol className="mt-2 list-decimal space-y-2 pl-5">
            <li>
              Add a DNS TXT record
              <code className="mt-1 block break-all rounded bg-paper p-1.5 text-xs">{ch.txt_name}</code>
              with value
              <code className="mt-1 block break-all rounded bg-paper p-1.5 text-xs">{ch.txt_value}</code>
            </li>
            <li>
              Or serve a plain-text file at
              <code className="mt-1 block break-all rounded bg-paper p-1.5 text-xs">{ch.file_url}</code>
              containing only
              <code className="mt-1 block break-all rounded bg-paper p-1.5 text-xs">{ch.file_body}</code>
            </li>
          </ol>
          <p className="mt-2 text-xs text-muted">This code expires in an hour. A verified site stays verified for 24 hours.</p>
          <button
            type="button"
            onClick={check}
            disabled={busy}
            className="mt-2 min-h-11 rounded bg-accent px-4 py-2 font-medium text-white disabled:opacity-60"
          >
            {busy ? "Checking…" : "Check"}
          </button>
        </>
      )}
      {err && (
        <p role="alert" className="mt-2 break-words text-c-mal-ink">
          {err}
        </p>
      )}
    </div>
  );
}
