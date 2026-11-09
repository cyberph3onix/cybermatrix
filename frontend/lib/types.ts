/**
 * Types generated from the FastAPI OpenAPI spec (lib/openapi.json → lib/api-types.ts).
 * Do not hand-write shapes here: change backend/app/schemas.py, then run `npm run gen`.
 * Datetimes are ISO-8601 strings. No floats.
 */
import type { components } from "./api-types";

type S = components["schemas"];

export type RiskClass = S["RiskClass"];
export type Severity = S["Severity"];
export type EvidenceStrength = S["EvidenceStrength"];
export type FindingCategory = S["FindingCategory"];
export type CheckStatus = S["CheckStatus"];
export type SubjectType = S["SubjectType"];
export type Confidence = S["Confidence"];
export type RegistryStatus = S["RegistryStatus"];
export type IndicatorType = S["Indicator"]["type"];

export type Evidence = S["Evidence"];
export type Finding = S["Finding"];
export type CheckRun = S["CheckRun"];
export type Indicator = S["Indicator"];
export type RedirectHop = S["RedirectHop"];
export type CertificateSummary = S["CertificateSummary"];
export type CertificateVerdict = S["CertificateVerdict"];
export type Coverage = S["Coverage"];
export type AIExplanation = S["AIExplanation"];
export type AssessmentReport = S["AssessmentReport"];
export type RegistryRecord = S["RegistryRecord"];
export type VerificationResult = S["VerificationResult"];
export type AssessRequest = S["AssessRequest"];
export type AssessResponse = S["AssessResponse"];
export type ClusterIndicator = S["ClusterIndicator"];
export type Cluster = S["Cluster"];
export type ReportHistory = S["ReportHistory"];
export type ReportVersion = S["ReportVersion"];
export type DisputeInfo = S["DisputeInfo"];
export type DisputePrepared = S["DisputePrepared"];
export type OwnershipChallenge = S["OwnershipChallenge"];
export type OwnershipGrant = S["OwnershipGrant"];
export type ImpersonationTrend = S["ImpersonationTrend"];
export type Watch = S["Watch"];
export type QuickCheck = S["QuickCheck"];
export type OrgDashboard = S["OrgDashboard"];
export type OrgDomain = S["OrgDomain"];
