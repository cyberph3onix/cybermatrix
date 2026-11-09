import type { CertificateSummary, CertificateVerdict } from "@/lib/types";

const VERDICT: Record<CertificateVerdict["verdict"], { label: string; cls: string }> = {
  valid: { label: "Valid: no certificate problems found", cls: "border-c-low bg-c-low-tint text-c-low-ink" },
  suspicious: { label: "Suspicious certificate", cls: "border-c-susp bg-c-susp-tint text-c-susp-ink" },
  potentially_compromised: {
    label: "Potentially compromised: issued under a distrusted or revoked authority",
    cls: "border-c-mal bg-c-mal-tint text-c-mal-ink",
  },
};

function VerdictBox({ v }: { v: CertificateVerdict }) {
  const style = VERDICT[v.verdict];
  return (
    <div className={`border-b p-3 text-sm sm:p-4 ${style.cls}`} data-testid="cert-verdict">
      <p className="font-semibold">Certificate verdict: {style.label}</p>
      {v.reasons.length > 0 && <p className="mt-1">Because of: {v.reasons.join(", ")}</p>}
      <dl className="mt-2 grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[11rem_1fr]">
        <dt>Trust problems</dt>
        <dd>{v.trust_findings.join(", ") || "none found"}</dd>
        <dt>Configuration problems</dt>
        <dd>{v.config_findings.join(", ") || "none found"}</dd>
      </dl>
      <p className="mt-2 text-xs">
        This verdict is about the certificate only and does not change the risk class above.
      </p>
    </div>
  );
}

const OCSP: Record<CertificateSummary["ocsp_status"], string> = {
  good: "Not revoked (OCSP good)",
  revoked: "Revoked",
  unknown: "OCSP responder gave no answer",
  unchecked: "Not checked",
};

const d = (s: string) => new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" });

export function CertificateCard({ cert, verdict }: { cert: CertificateSummary; verdict?: CertificateVerdict | null }) {
  const rows: [string, React.ReactNode][] = [
    ["Issued to", cert.subject_cn ?? "—"],
    ["Issuer", cert.issuer],
    ["Chain", cert.chain_issuers.join(" → ") || "—"],
    ["Valid", `${d(cert.not_before)} to ${d(cert.not_after)} (${cert.days_remaining} days left)`],
    ["Key", `${cert.key_type} ${cert.key_bits}-bit, ${cert.signature_algorithm}`],
    ["Chain validates", cert.chain_valid ? "Yes, against the root stores we checked" : "No"],
    ["Revocation", OCSP[cert.ocsp_status]],
    [
      "Certificate Transparency",
      `${cert.ct_sct_count} SCTs${
        cert.ct_logged_in_crtsh === null ? "" : cert.ct_logged_in_crtsh ? ", found in public log search" : ", not found in public log search"
      }`,
    ],
    ["TLS version", cert.tls_version ?? "—"],
    ["Names (SAN)", cert.san.join(", ") || "—"],
    ["SHA-256", <span key="fp" className="break-all font-mono text-xs">{cert.sha256_fingerprint}</span>],
  ];
  return (
    <div className="rounded-md border border-rule bg-panel">
      <p className="border-b border-rule bg-amber-50 p-3 text-sm font-medium text-amber-950 sm:p-4">
        A valid certificate does not mean the site is legitimate. It shows the connection is
        encrypted to whoever holds this domain, and anyone can get one.
      </p>
      {verdict && <VerdictBox v={verdict} />}
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 p-3 text-sm sm:grid-cols-[11rem_1fr] sm:p-4">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-muted">{k}</dt>
            <dd className="min-w-0 break-words">{v}</dd>
          </div>
        ))}
      </dl>
      <p className="border-t border-rule p-3 text-xs text-muted sm:p-4">
        We flag certificates from known-distrusted or compromised authorities using curated lists,
        revocation status and Certificate Transparency. We cannot detect weaknesses in how a
        certificate authority generates its keys from a URL.
      </p>
    </div>
  );
}
