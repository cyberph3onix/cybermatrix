import type { Confidence, EvidenceStrength, RiskClass, Severity } from "./types";

/**
 * Display config per risk class. Each class has its own colour AND its own
 * glyph shape, so the banner never relies on colour alone. The word "safe"
 * must never appear here (CLAUDE.md rule 3).
 */
export interface ClassStyle {
  label: string;
  headline: string;
  glyph: "ring" | "triangle" | "octagon" | "cross" | "dash";
  bar: string; // solid colour for left bar / glyph
  tint: string; // background
  text: string; // text colour on tint
  border: string;
}

export const CLASS_STYLE: Record<RiskClass, ClassStyle> = {
  low_risk: {
    label: "Low risk",
    headline: "No significant malicious indicators within the checks performed.",
    glyph: "ring",
    bar: "bg-c-low",
    tint: "bg-c-low-tint",
    text: "text-c-low-ink",
    border: "border-c-low",
  },
  suspicious: {
    label: "Suspicious",
    headline: "Some signals look like phishing or abuse. Treat with caution.",
    glyph: "triangle",
    bar: "bg-c-susp",
    tint: "bg-c-susp-tint",
    text: "text-c-susp-ink",
    border: "border-c-susp",
  },
  high_risk: {
    label: "High risk",
    headline: "Strong technical signals of phishing or abuse.",
    glyph: "octagon",
    bar: "bg-c-high",
    tint: "bg-c-high-tint",
    text: "text-c-high-ink",
    border: "border-c-high",
  },
  confirmed_malicious: {
    label: "Confirmed malicious",
    headline: "Matched an authoritative threat source, or several corroborating signals.",
    glyph: "cross",
    bar: "bg-c-mal",
    tint: "bg-c-mal-tint",
    text: "text-c-mal-ink",
    border: "border-c-mal",
  },
  inconclusive: {
    label: "Inconclusive",
    headline: "Too few checks completed to reach a reliable conclusion.",
    glyph: "dash",
    bar: "bg-c-inc",
    tint: "bg-c-inc-tint",
    text: "text-c-inc-ink",
    border: "border-c-inc",
  },
};

export const SEVERITY_STYLE: Record<Severity, { label: string; cls: string }> = {
  info: { label: "Info", cls: "bg-slate-100 text-slate-700 border-slate-300" },
  low: { label: "Low", cls: "bg-sky-50 text-sky-900 border-sky-300" },
  medium: { label: "Medium", cls: "bg-amber-50 text-amber-900 border-amber-400" },
  high: { label: "High", cls: "bg-orange-50 text-orange-900 border-orange-400" },
  critical: { label: "Critical", cls: "bg-red-50 text-red-900 border-red-500" },
};

export const STRENGTH_INFO: Record<
  EvidenceStrength,
  { label: string; cls: string; blurb: string }
> = {
  authoritative: {
    label: "Authoritative",
    cls: "bg-ink text-white border-ink",
    blurb: "Reported by a trusted external source, such as a threat-intelligence feed.",
  },
  technical: {
    label: "Technical",
    cls: "bg-white text-ink border-ink",
    blurb: "Directly observed by our own inspection, such as a page form or a certificate field.",
  },
  heuristic: {
    label: "Heuristic",
    cls: "bg-white text-muted border-muted border-dashed",
    blurb: "A pattern that often goes with abuse but can also appear on legitimate sites.",
  },
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
};

export const CATEGORY_LABEL: Record<string, string> = {
  phishing: "Phishing behaviour",
  impersonation: "Impersonation",
  redirect: "Redirects",
  threat_intel: "Threat intelligence",
  domain: "Domain",
  tls_trust: "Certificate trust",
  tls_config: "TLS configuration",
  social_engineering: "Social engineering",
  correlation: "Related reports",
  security_posture: "Security posture",
};

export const CHECK_GROUP_LABEL: Record<string, string> = {
  "url.structure": "URL structure",
  "intel.gsb": "Google Safe Browsing",
  "intel.urlhaus": "URLhaus",
  "intel.openphish": "OpenPhish",
  "intel.virustotal": "VirusTotal",
  "fetch.redirects": "Redirects",
  "page.content": "Page content",
  "tls.chain": "Certificate chain",
  "tls.revocation": "Revocation",
  "tls.ct": "Certificate Transparency",
  "domain.rdap": "Domain registration",
  "domain.dns": "DNS",
  "url.lookalike": "Look-alike domains",
  "page.llm": "AI page reading",
  "page.screenshot": "AI screenshot reading",
  "posture.headers": "Security headers",
  "message.extract": "Message analysis",
  "message.signals": "AI language signals",
  "message.urls": "Links in the message",
  "upi.payee": "UPI payee",
};

/** Display names for indicator types. */
export const INDICATOR_LABEL: Record<string, string> = {
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
  brand_claimed: "Brand claimed",
};
