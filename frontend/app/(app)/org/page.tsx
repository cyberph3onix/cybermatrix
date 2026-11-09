"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { createOrg, getOrg, scanOrg } from "@/lib/api";
import { CLASS_STYLE } from "@/lib/classes";
import type { OrgDashboard, OrgDomain } from "@/lib/types";

const KEY = "cm.org_ids";
const WATCH_KEY = "cm.watch_ids";
const when = (s: string) => new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

function load(key: string): string[] {
  try {
    return JSON.parse(localStorage.getItem(key) ?? "[]") as string[];
  } catch {
    return [];
  }
}

function save(key: string, ids: string[]) {
  try {
    localStorage.setItem(key, JSON.stringify(ids));
  } catch {
    /* private window: the dashboard still exists, keep its ID */
  }
}

function DomainRow({ d }: { d: OrgDomain }) {
  const latest = d.latest;
  const style = latest ? CLASS_STYLE[latest.classification] : null;
  const p = latest?.posture;
  return (
    <li className="rounded-md border border-rule bg-panel p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="break-all text-lg font-semibold">{d.domain}</h3>
        {latest && style ? (
          <Link
            href={`/report/${latest.report_id}`}
            className={`rounded border px-2 py-0.5 text-sm font-medium ${style.border} ${style.tint} ${style.text}`}
          >
            {style.label} · {latest.coverage_percent}% coverage
          </Link>
        ) : (
          <span className="text-sm text-muted">Not assessed yet. Run a scan.</span>
        )}
      </div>

      <dl className="mt-3 grid grid-cols-1 gap-3 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-muted">Security posture</dt>
          <dd className="font-medium">
            {p ? (
              p.high + p.medium + p.low === 0 ? (
                "No posture findings"
              ) : (
                <>
                  <span className={p.high ? "text-c-high-ink" : ""}>{p.high} high</span> · {p.medium} medium · {p.low} low
                </>
              )
            ) : (
              "—"
            )}
          </dd>
          {latest && <dd className="text-xs text-muted">checked {when(latest.created_at)}</dd>}
        </div>
        <div>
          <dt className="text-muted">New certificates (CT)</dt>
          <dd className="font-medium">
            <span className={d.ct_new_issuer_alerts ? "text-c-high-ink" : ""}>{d.ct_alerts}</span>
            {d.ct_new_issuer_alerts > 0 && <span className="text-c-high-ink"> ({d.ct_new_issuer_alerts} from a new CA)</span>}
          </dd>
          <dd className="text-xs text-muted">
            {d.ct_last_checked ? `logs read ${when(d.ct_last_checked)}` : "baseline pending"}
            {d.watch_id && (
              <>
                {" · "}
                <Link className="text-accent underline" href="/watch">
                  details
                </Link>
              </>
            )}
          </dd>
        </div>
        <div>
          <dt className="text-muted">Impersonation reports</dt>
          <dd className={`font-medium ${d.impersonation.reports ? "text-c-mal-ink" : ""}`}>{d.impersonation.reports}</dd>
          {d.impersonation.lookalike_domains.length > 0 && (
            <dd className="break-all font-mono text-xs">{d.impersonation.lookalike_domains.join(", ")}</dd>
          )}
        </div>
      </dl>

      {latest && latest.posture_titles.length > 0 && (
        <ul className="mt-3 list-disc pl-5 text-sm">
          {latest.posture_titles.map((t) => (
            <li key={t}>{t}</li>
          ))}
        </ul>
      )}
      {d.impersonation.report_ids.length > 0 && (
        <p className="mt-2 text-sm">
          Latest:{" "}
          {d.impersonation.report_ids.map((id, i) => (
            <span key={id}>
              {i > 0 && ", "}
              <Link className="font-mono text-accent underline" href={`/report/${id}`}>
                {id.slice(0, 8)}
              </Link>
            </span>
          ))}
        </p>
      )}
    </li>
  );
}

function Dashboard({ org, onUpdate }: { org: OrgDashboard; onUpdate: (o: OrgDashboard) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const issues = org.domains.filter(
    (d) => (d.latest?.posture.high ?? 0) > 0 || d.ct_new_issuer_alerts > 0 || d.impersonation.reports > 0,
  ).length;

  async function scan() {
    setBusy(true);
    setErr(null);
    try {
      onUpdate(await scanOrg(org.org_id));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Scan failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-labelledby={`o-${org.org_id}`} className="mt-10">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 id={`o-${org.org_id}`} className="text-2xl font-semibold">
            {org.name}
          </h2>
          <p className="text-sm text-muted">
            {org.domains.length} domain{org.domains.length === 1 ? "" : "s"} ·{" "}
            {issues === 0 ? "nothing needs attention" : `${issues} need${issues === 1 ? "s" : ""} attention`} · last scan{" "}
            {org.last_scan ? when(org.last_scan) : "never"}
          </p>
        </div>
        <button
          type="button"
          onClick={scan}
          disabled={busy}
          className="min-h-11 rounded bg-accent px-5 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Scanning… (up to a minute)" : "Scan all domains"}
        </button>
      </div>
      {err && (
        <p role="alert" className="mt-3 text-sm text-c-mal-ink">
          {err}
        </p>
      )}
      <ul className="mt-4 space-y-4">
        {org.domains.map((d) => (
          <DomainRow key={d.domain} d={d} />
        ))}
      </ul>
      <p className="mt-3 text-xs text-muted">
        Dashboard ID <code className="break-all">{org.org_id}</code>, saved in this browser. {org.note}
      </p>
    </section>
  );
}

export default function OrgPage() {
  const [name, setName] = useState("");
  const [domains, setDomains] = useState("");
  const [orgs, setOrgs] = useState<OrgDashboard[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    Promise.all(load(KEY).map((id) => getOrg(id).catch(() => null))).then((os) =>
      setOrgs(os.filter((o): o is OrgDashboard => o !== null)),
    );
  }, []);

  const update = (o: OrgDashboard) => setOrgs((os) => os.map((x) => (x.org_id === o.org_id ? o : x)));

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const list = domains.split(/[\s,]+/).filter(Boolean);
      const o = await createOrg(name.trim(), list);
      save(KEY, [o.org_id, ...load(KEY).filter((x) => x !== o.org_id)]);
      const wids = o.domains.map((d) => d.watch_id).filter((x): x is string => !!x);
      save(WATCH_KEY, [...wids, ...load(WATCH_KEY).filter((x) => !wids.includes(x))]); // also listed on CT watch
      setOrgs((os) => [o, ...os.filter((x) => x.org_id !== o.org_id)]);
      setName("");
      setDomains("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't create the dashboard.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-3xl">
      <h1 className="text-3xl font-semibold leading-tight">Organisation dashboard</h1>
      <p className="mt-3 max-w-prose text-muted">
        Monitor all of your organisation&apos;s websites in one place: security posture (headers, TLS hygiene, exposed
        software versions), new certificates issued for your domains, and lookalike sites reported to CyberMatrix.
        Every check is passive and uses public information.
      </p>

      <form onSubmit={create} className="mt-6 space-y-3 rounded-md border border-rule bg-panel p-4">
        <div>
          <label htmlFor="oname" className="block font-medium">
            Organisation name
          </label>
          <input
            id="oname"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={80}
            placeholder="Example Bank"
            className="mt-1 min-h-11 w-full rounded border border-rule bg-paper px-3 text-base"
          />
        </div>
        <div>
          <label htmlFor="odomains" className="block font-medium">
            Domains (one per line, up to 20)
          </label>
          <textarea
            id="odomains"
            rows={4}
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            placeholder={"examplebank.com\nexamplebank-online.in"}
            className="mt-1 w-full rounded border border-rule bg-paper p-3 font-mono text-sm"
            spellCheck={false}
          />
        </div>
        <button
          type="submit"
          disabled={busy || !name.trim() || !domains.trim()}
          className="min-h-11 rounded bg-accent px-5 font-medium text-white disabled:opacity-50"
        >
          {busy ? "Setting up monitoring…" : "Create dashboard"}
        </button>
        {err && (
          <p role="alert" className="text-sm text-c-mal-ink">
            {err}
          </p>
        )}
      </form>

      {orgs.map((o) => (
        <Dashboard key={o.org_id} org={o} onUpdate={update} />
      ))}
    </div>
  );
}
