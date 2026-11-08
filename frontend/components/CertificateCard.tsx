import type { CertificateSummary } from "@/lib/types";

const OCSP: Record<CertificateSummary["ocsp_status"], string> = {
  good: "Not revoked (OCSP good)",
  revoked: "Revoked",
  unknown: "OCSP responder gave no answer",
  unchecked: "Not checked",
};

const d = (s: string) => new Date(s).toLocaleDateString(undefined, { dateStyle: "medium" });

export function CertificateCard({ cert }: { cert: CertificateSummary }) {
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
