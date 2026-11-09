"use client";

import { useEffect, useState } from "react";
import { createWatch, getWatch } from "@/lib/api";
import type { Watch } from "@/lib/types";

const KEY = "cm.watch_ids";
const day = (s: string) => new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

function savedIds(): string[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? "[]") as string[];
  } catch {
    return [];
  }
}

function saveIds(ids: string[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(ids));
  } catch {
    /* private window: the watch still exists, keep its ID */
  }
}

export default function WatchPage() {
  const [domain, setDomain] = useState("");
  const [watches, setWatches] = useState<Watch[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    Promise.all(savedIds().map((id) => getWatch(id).catch(() => null))).then((ws) =>
      setWatches(ws.filter((w): w is Watch => w !== null)),
    );
  }, []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const w = await createWatch(domain);
      saveIds([w.watch_id, ...savedIds().filter((x) => x !== w.watch_id)]);
      setWatches((ws) => [w, ...ws.filter((x) => x.watch_id !== w.watch_id)]);
      setDomain("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't start the watch.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="text-3xl font-semibold leading-tight">Certificate watch</h1>
      <p className="mt-3 max-w-prose text-muted">
        Get told when a new TLS certificate is issued for your domain or any of its subdomains. A certificate you
        didn&apos;t request, or one from a CA you don&apos;t use, can mean someone is preparing to impersonate you.
        We read public Certificate Transparency logs (Cert Spotter) about every hour.
      </p>

      <form onSubmit={add} className="mt-6 flex flex-wrap gap-2">
        <label htmlFor="domain" className="sr-only">
          Domain
        </label>
        <input
          id="domain"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="yourcompany.com"
          className="min-h-11 min-w-0 flex-1 rounded border border-rule bg-panel px-3 text-base"
          autoComplete="off"
        />
        <button
          type="submit"
          disabled={busy || domain.trim().length < 3}
          className="min-h-11 rounded bg-accent px-5 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Reading CT logs…" : "Watch"}
        </button>
      </form>
      {err && (
        <p role="alert" className="mt-3 text-sm text-c-mal-ink">
          {err}
        </p>
      )}

      <ul className="mt-8 space-y-5">
        {watches.map((w) => (
          <li key={w.watch_id} className="rounded-md border border-rule bg-panel p-4">
            <h2 className="text-lg font-semibold">{w.domain}</h2>
            <p className="mt-1 text-sm text-muted">
              {w.known_certificates} certificates known · CAs: {w.known_issuers.join(", ") || "none yet"} · last checked{" "}
              {w.last_checked ? day(w.last_checked) : "pending"}
            </p>
            {w.alerts.length === 0 ? (
              <p className="mt-3 text-sm">No new certificates since the watch started.</p>
            ) : (
              <ul className="mt-3 divide-y divide-rule text-sm">
                {w.alerts.map((a) => (
                  <li key={a.cert_sha256} className="py-2">
                    <p>
                      <span className={a.new_issuer ? "font-semibold text-c-high-ink" : "font-medium"}>
                        {a.new_issuer ? "New CA: " : ""}
                        {a.issuer}
                      </span>{" "}
                      <span className="text-muted">· seen {day(a.seen_at)}</span>
                    </p>
                    <p className="break-all font-mono text-xs">{a.dns_names.join(", ")}</p>
                    <a
                      className="text-xs text-accent underline"
                      href={`https://crt.sh/?q=${a.cert_sha256}`}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      View certificate on crt.sh
                    </a>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-3 text-xs text-muted">
              Watch ID <code className="break-all">{w.watch_id}</code>, saved in this browser. {w.note}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
