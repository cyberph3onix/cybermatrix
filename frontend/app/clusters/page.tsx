"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getClusters } from "@/lib/api";
import { CLASS_STYLE } from "@/lib/classes";
import type { Cluster } from "@/lib/types";

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
};

const day = (s: string) => new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" });

export default function ClustersPage() {
  const [clusters, setClusters] = useState<Cluster[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    getClusters().then(setClusters).catch(() => setErr("Couldn't load clusters. Reload to try again."));
  }, []);

  return (
    <div>
      <h1 className="text-3xl font-semibold leading-tight">Incident clusters</h1>
      <p className="mt-3 max-w-prose text-muted">
        Reports that share infrastructure or contact details are grouped here. A shared indicator
        suggests a common operator, but it is a lead, not proof.
      </p>

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

                  <h3 className="mt-4 text-sm font-semibold">Domains seen</h3>
                  <p className="mt-1 break-all font-mono text-xs sm:text-sm">{c.member_domains.join(", ")}</p>

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
