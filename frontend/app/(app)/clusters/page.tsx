"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { feedUrls, getClusters, getImpersonationTrends } from "@/lib/api";
import { CLASS_STYLE } from "@/lib/classes";
import type { Cluster, ImpersonationTrend } from "@/lib/types";

const TYPE_LABEL: Record<string, string> = {
  ip: "IP address",
  domain: "Domain",
  nameserver: "Name server",
  cert_sha256: "Certificate",
  upi_id: "UPI ID",
  phone: "Phone",
  email: "Email",
  crypto_address: "Crypto address",
  asn: "ASN",
  url: "URL",
  message_family: "Message wording",
};

const day = (s: string) => new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" });

export default function ClustersPage() {
  const [clusters, setClusters] = useState<Cluster[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [trends, setTrends] = useState<ImpersonationTrend[]>([]);

  useEffect(() => {
    getClusters().then(setClusters).catch(() => setErr("Couldn't load clusters. Reload to try again."));
    getImpersonationTrends().then(setTrends).catch(() => {});
  }, []);

  return (
    <div>
      <h1 className="text-3xl font-semibold leading-tight">Incident clusters</h1>
      <p className="mt-3 max-w-prose text-muted">
        Reports that share infrastructure or contact details are grouped here. A shared indicator
        suggests a common operator, but it is a lead, not proof.
      </p>

      <section aria-labelledby="feed" className="mt-6 rounded-md border border-rule bg-panel p-4">
        <h2 id="feed" className="font-semibold">
          Share these indicators
        </h2>
        <p className="mt-1 text-sm text-muted">
          Links and domains from high-risk reports, ready for a firewall, mail filter or SIEM. Query strings are
          removed, redirect hops and well-known sites are never listed, and reports a validator rejected on-chain
          are left out.
        </p>
        <p className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm">
          <a className="text-accent underline" href={feedUrls().stix} target="_blank" rel="noopener noreferrer">
            STIX 2.1 bundle
          </a>
          <a className="text-accent underline" href={feedUrls().blocklist} target="_blank" rel="noopener noreferrer">
            Plain-text blocklist
          </a>
          <a
            className="text-accent underline"
            href={feedUrls("suspicious").stix}
            target="_blank"
            rel="noopener noreferrer"
          >
            Include suspicious (STIX)
          </a>
        </p>
      </section>

      {trends.length > 0 && (
        <section aria-labelledby="trends" className="mt-8">
          <h2 id="trends" className="text-lg font-semibold">Most impersonated brands</h2>
          <p className="mt-1 max-w-prose text-sm text-muted">
            Brands that suspicious reports on this server pretend to be. Counted from findings, not guessed.
          </p>
          <ul className="mt-3 divide-y divide-rule rounded-md border border-rule bg-panel text-sm">
            {trends.map((t) => (
              <li key={t.brand_id} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-2">
                <span className="min-w-0 flex-1 font-medium">{t.brand}</span>
                <span>
                  {t.reports} reports ({t.links} links, {t.messages} messages)
                </span>
                <span className="text-xs text-muted">last {day(t.last_seen)}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {err && <p role="alert" className="mt-6 text-c-mal-ink">{err}</p>}
      {!clusters && !err && <p role="status" className="mt-6 text-muted">Loading clusters…</p>}
      {clusters?.length === 0 && (
        <p className="mt-6">No clusters yet. Clusters form when two reports share an indicator.</p>
      )}

      <ul className="mt-8 space-y-5">
        {clusters?.map((c) => {
          const s = CLASS_STYLE[c.top_classification];
          return (
            <li key={c.cluster_id} className="overflow-hidden rounded-md border border-rule bg-panel">
              <div className="flex">
                <div className={`w-1.5 shrink-0 ${s.bar}`} aria-hidden />
                <div className="min-w-0 flex-1 p-4">
                  <h2 className="text-lg font-semibold">{c.label}</h2>
                  <p className="mt-1 text-sm text-muted">
                    {c.report_ids.length} reports · highest class:{" "}
                    <span className={`font-medium ${s.text}`}>{s.label}</span> · {day(c.first_seen)} to {day(c.last_seen)}
                  </p>
                  {c.summary && (
                    <p className="mt-3 text-sm">
                      {c.summary}{" "}
                      <span className="text-xs text-muted">AI-written description ({c.summary_model}); the grouping itself is rule-based.</span>
                    </p>
                  )}

                  <h3 className="mt-4 text-sm font-semibold">Shared indicators</h3>
                  <ul className="mt-1 divide-y divide-rule text-sm">
                    {c.shared_indicators.map((i) => (
                      <li key={i.type + i.value} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 py-1.5">
                        <span className="w-28 shrink-0 text-muted">{TYPE_LABEL[i.type] ?? i.type}</span>
                        <code className="min-w-0 flex-1 break-all font-mono text-xs sm:text-sm">{i.value}</code>
                        <span className="text-xs text-muted">in {i.report_count} of {c.report_ids.length}</span>
                      </li>
                    ))}
                  </ul>

                  {c.member_domains.length > 0 && (
                    <>
                      <h3 className="mt-4 text-sm font-semibold">Domains seen</h3>
                      <p className="mt-1 break-all font-mono text-xs sm:text-sm">{c.member_domains.join(", ")}</p>
                    </>
                  )}

                  <p className="mt-4 text-sm">
                    Reports:{" "}
                    {c.report_ids.map((rid, i) => (
                      <span key={rid}>
                        {i > 0 && ", "}
                        <Link className="font-mono text-xs text-accent underline" href={`/report/${rid}`}>
                          {rid.slice(0, 8)}
                        </Link>
                      </span>
                    ))}
                  </p>
                </div>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
