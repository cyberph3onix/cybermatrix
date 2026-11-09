/**
 * Hand-written mirror of backend/app/schemas.py (schema_version 1.0.0).
 * To be replaced by OpenAPI codegen. Datetimes are ISO-8601 strings. No floats.
 */

export type RiskClass =
  | "low_risk"
  | "suspicious"
  | "high_risk"
  | "confirmed_malicious"
  | "inconclusive";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type EvidenceStrength = "authoritative" | "technical" | "heuristic";

export type FindingCategory =
  | "phishing"
  | "impersonation"
  | "redirect"
  | "threat_intel"
  | "domain"
  | "tls_trust"
  | "tls_config"
  | "social_engineering"
  | "correlation"
  | "security_posture";

export type CheckStatus = "completed" | "failed" | "unavailable" | "skipped";
export type SubjectType = "url" | "domain" | "message" | "email" | "qr";
export type Confidence = "high" | "medium" | "low";
export type RegistryStatus =
  | "submitted"
  | "disputed"
  | "validated"
  | "rejected"
  | "superseded";

export type IndicatorType =
  | "url"
  | "domain"
  | "ip"
  | "asn"
  | "nameserver"
  | "cert_sha256"
  | "email"
  | "phone"
  | "upi_id"
  | "crypto_address";

export interface Evidence {
  kind: string;
  description: string;
  data: Record<string, unknown>;
  source: string;
  observed_at: string;
}

export interface Finding {
  check_id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  strength: EvidenceStrength;
  evidence: Evidence[];
  impact: string;
  recommendation: string;
  limitation: string | null;
  indicator_ref: string | null;
}

export interface CheckRun {
  check_group: string;
  status: CheckStatus;
  source: string;
  duration_ms: number;
  weight: number;
  detail: string | null;
}

export interface Indicator {
  type: IndicatorType;
  value: string;
  normalized: string;
}

export interface RedirectHop {
  url: string;
  status_code: number;
  resolved_ip: string | null;
  cross_domain: boolean;
}

export interface CertificateSummary {
  subject_cn: string | null;
  san: string[];
  issuer: string;
  chain_issuers: string[];
  not_before: string;
  not_after: string;
  days_remaining: number;
  key_type: "RSA" | "EC" | "Ed25519" | "other";
  key_bits: number;
  signature_algorithm: string;
  sha256_fingerprint: string;
  ocsp_status: "good" | "revoked" | "unknown" | "unchecked";
  ct_sct_count: number;
  ct_logged_in_crtsh: boolean | null;
  chain_valid: boolean;
  tls_version: string | null;
}

export interface Coverage {
  percent: number;
  completed: string[];
  unavailable: string[];
  failed: string[];
  skipped: string[];
}

export interface AIExplanation {
  model: string;
  summary: string;
  language_signals: string[];
  verified_evidence_refs: string[];
  injection_attempt_detected: boolean;
  disclaimer: string;
}

export interface AssessmentReport {
  schema_version: string;
  report_id: string;
  salt: string;
  created_at: string;
  subject_type: SubjectType;
  subject: string;
  normalized_subject: string;
  classification: RiskClass;
  classification_reason: string;
  score: number;
  confidence: Confidence;
  coverage: Coverage;
  findings: Finding[];
  security_posture: Finding[];
  check_runs: CheckRun[];
  indicators: Indicator[];
  redirect_chain: RedirectHop[];
  certificate: CertificateSummary | null;
  ai: AIExplanation | null;
  recommended_actions: string[];
  limitations: string[];
  related_report_ids: string[];
}

export interface RegistryRecord {
  report_id: string;
  report_hash: string;
  parent_hash: string;
  chain_id: number;
  contract_address: string;
  onchain_id: number | null;
  tx_hash: string | null;
  reporter_address: string | null;
  status: RegistryStatus;
}

export interface VerificationResult {
  report_id: string;
  computed_hash: string;
  onchain_hash: string | null;
  match: boolean;
  onchain_status: RegistryStatus | null;
  onchain_created_at: string | null;
  tx_hash: string | null;
  explorer_url: string | null;
  note: string;
}

export interface AssessRequest {
  input: string;
  subject_type?: SubjectType | null;
}

/**
 * NOT in schemas.py yet: GET /clusters has no backend model. This shape is a
 * proposal; align it with the backend once correlation/clusters.py exists.
 */
export interface ClusterIndicator {
  type: IndicatorType;
  value: string;
  /** How many member reports contain this indicator. */
  report_count: number;
}

export interface Cluster {
  cluster_id: string;
  label: string;
  first_seen: string;
  last_seen: string;
  report_ids: string[];
  top_classification: RiskClass;
  shared_indicators: ClusterIndicator[];
  member_domains: string[];
}
