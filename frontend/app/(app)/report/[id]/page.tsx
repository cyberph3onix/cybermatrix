"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { getCertificateVerdict, getReport } from "@/lib/api";
import type { AssessmentReport, CertificateVerdict } from "@/lib/types";
import { AiBox } from "@/components/AiBox";
import { StrengthLegend } from "@/components/Badges";
import { CertificateCard } from "@/components/CertificateCard";
import { ClassBanner } from "@/components/ClassBanner";
import { FindingGroups } from "@/components/FindingGroups";
import { InvestigationTrace } from "@/components/InvestigationTrace";
import { RedirectTimeline } from "@/components/RedirectTimeline";
import { Provenance } from "@/components/Provenance";
import { RegisterButton } from "@/components/RegisterButton";
import { Section } from "@/components/Section";

export default function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [report, setReport] = useState<AssessmentReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [certVerdict, setCertVerdict] = useState<CertificateVerdict | null>(null);

  useEffect(() => {
    let live = true;
    getReport(id)
      .then((r) => live && setReport(r))
      .catch((e) => live && setErr(e instanceof Error ? e.message : "Couldn't load this report."));
    getCertificateVerdict(id)
      .then((v) => live && setCertVerdict(v))
      .catch(() => undefined); // optional: the card still renders without it
    return () => {
      live = false;
    };
  }, [id]);

  if (err) {
    return (
      <div role="alert" className="rounded-md border border-c-mal bg-c-mal-tint p-4 text-c-mal-ink">
        <p className="font-medium">{err}</p>
        <p className="mt-1 text-sm">
          Check the address, or <Link className="underline" href="/investigate">start a new investigation</Link>.
        </p>
      </div>
    );
  }
  if (!report) return <p role="status" className="text-muted">Loading report…</p>;

  return (
    <article>
      <div className="mb-4">
        <p className="text-sm text-muted">
          {report.subject_type === "message" ? "Message (personal details masked)" : "Subject"}
        </p>
        <p className="break-all font-mono text-sm">{report.subject}</p>
      </div>

      <ClassBanner report={report} />

      {report.incident_summary && (
        <Section id="summary" title="What the submitter reported">
          <p className="max-w-prose whitespace-pre-wrap text-sm">{report.incident_summary}</p>
          <p className="mt-1 text-xs text-muted">In the submitter&apos;s own words, personal details masked. Not checked by us.</p>
        </Section>
      )}

      {report.recommended_actions.length > 0 && (
        <Section id="actions" title="What to do now">
          <ul className="max-w-prose list-disc space-y-1 pl-5">
            {report.recommended_actions.map((a) => (
              <li key={a}>{a}</li>
            ))}
          </ul>
        </Section>
      )}

      <Section
        id="investigation"
        title="How we investigated"
        intro="Every question we asked, which sources answered, what each one found, and how the rules reached the verdict."
      >
        <InvestigationTrace report={report} />
      </Section>

      {report.ai && (
        <Section id="ai" title="Plain-language explanation">
          <AiBox ai={report.ai} />
        </Section>
      )}

      <Section
        id="findings"
        title={`Findings (${report.findings.length})`}
        intro="Each finding opens to show its evidence, where that evidence came from, and what we can't tell from it."
      >
        <div className="mb-5 rounded-md border border-rule bg-panel p-3">
          <p className="mb-2 text-sm font-medium">How strong is the evidence?</p>
          <StrengthLegend />
        </div>
        <FindingGroups findings={report.findings} />
      </Section>

      <Section id="redirects" title="Redirect chain">
        <RedirectTimeline hops={report.redirect_chain} />
      </Section>

      {report.certificate && (
        <Section id="cert" title="Certificate">
          <CertificateCard cert={report.certificate} verdict={certVerdict} />
        </Section>
      )}

      <Section
        id="posture"
        title="Site security posture"
        intro="Configuration hygiene such as missing headers. These items are reported separately and do not change the risk class above, because plenty of legitimate sites have them."
      >
        {report.security_posture.length > 0 ? (
          <FindingGroups findings={report.security_posture} />
        ) : (
          <p className="text-sm text-muted">No posture issues were reported.</p>
        )}
      </Section>

      <Section id="limits" title="Limitations">
        <ul className="max-w-prose list-disc space-y-1.5 pl-5 text-sm">
          {report.limitations.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </Section>

      <Section id="register" title="Community registry">
        <RegisterButton reportId={report.report_id} />
      </Section>

      <Section id="provenance" title="Fingerprints and provenance">
        <Provenance reportId={report.report_id} />
      </Section>

      <p className="mt-10 break-all font-mono text-xs text-muted">
        Report {report.report_id} · schema {report.schema_version}
      </p>
    </article>
  );
}
