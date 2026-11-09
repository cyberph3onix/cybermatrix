/**
 * API client. Every call is mocked from backend/tests/fixtures/sample_report.json
 * (copied to lib/mock by scripts/sync-fixture.mjs). Swap the bodies for fetch()
 * calls to the FastAPI routes when the backend is ready; signatures match them:
 *   POST /assess, POST /assess/qr, GET /reports/{id}, POST /reports/{id}/register,
 *   GET /reports/{id}/verify, GET /clusters
 */
import sample from "./mock/sample_report.json";
import { MOCK_CLUSTERS } from "./mock/clusters";
import { reportHash } from "./hash";
import type {
  AssessRequest,
  AssessmentReport,
  Cluster,
  RegistryRecord,
  RiskClass,
  VerificationResult,
} from "./types";

const FIXTURE = sample as unknown as AssessmentReport;
const CHAIN_ID = 11155111; // Sepolia
const MOCK_CONTRACT = "0x5a3c1e7d9b2f4a6c8e0d1f3b5a7c9e2d4f6a8b0c";
const MOCK_TX = "0x" + "c4".repeat(32);
const MOCK_REPORTER = "0x9b1e4d7a2c5f8b3e6a0d1c4f7b2e5a8d3c6f9b1e";

const wait = (ms = 450) => new Promise((r) => setTimeout(r, ms));

const CLASSES: RiskClass[] = [
  "low_risk",
  "suspicious",
  "high_risk",
  "confirmed_malicious",
  "inconclusive",
];

export class ApiError extends Error {}

/**
 * Mock-only: ids like "demo-low_risk" return the fixture with a different
 * class so every banner can be previewed. Remove with the mock.
 */
function withPreviewClass(id: string): AssessmentReport {
  const cls = CLASSES.find((c) => id === `demo-${c}`);
  if (!cls) return FIXTURE;
  return {
    ...FIXTURE,
    report_id: id,
    classification: cls,
    classification_reason: `Preview of the "${cls}" banner using fixture data`,
    confidence: cls === "inconclusive" ? "low" : FIXTURE.confidence,
    coverage:
      cls === "inconclusive"
        ? {
            percent: 30,
            completed: ["url.structure", "intel.gsb"],
            unavailable: ["intel.virustotal", "intel.urlhaus", "domain.rdap"],
            failed: ["fetch.redirects", "page.content"],
            skipped: ["tls.chain", "tls.revocation", "tls.ct"],
          }
        : FIXTURE.coverage,
  };
}

export async function assess(req: AssessRequest): Promise<{ report_id: string }> {
  await wait(900);
  if (!req.input.trim()) throw new ApiError("Enter a link, domain, email or message.");
  return { report_id: FIXTURE.report_id };
}

export async function assessQr(file: File): Promise<{ report_id: string }> {
  await wait(900);
  if (!file.type.startsWith("image/")) throw new ApiError("Upload an image file (PNG or JPG).");
  return { report_id: FIXTURE.report_id };
}

export async function getReport(id: string): Promise<AssessmentReport> {
  await wait(350);
  if (id === FIXTURE.report_id || id.startsWith("demo-")) return withPreviewClass(id);
  throw new ApiError("No report with this ID.");
}

const registered = new Map<string, RegistryRecord>();

export async function getRegistration(id: string): Promise<RegistryRecord | null> {
  await wait(200);
  return registered.get(id) ?? null;
}

export async function registerReport(id: string): Promise<RegistryRecord> {
  await wait(1600);
  const report = await getReport(id);
  const rec: RegistryRecord = {
    report_id: id,
    report_hash: reportHash(report),
    parent_hash: "0x" + "00".repeat(32),
    chain_id: CHAIN_ID,
    contract_address: MOCK_CONTRACT,
    onchain_id: 1,
    tx_hash: MOCK_TX,
    reporter_address: MOCK_REPORTER,
    status: "submitted",
  };
  registered.set(id, rec);
  return rec;
}

/**
 * Mock on-chain lookup. The fixture counts as "already registered" so the
 * verify page has a MATCH to show; editing an uploaded copy gives a MISMATCH.
 */
function mockOnchainHash(reportId: string): string | null {
  if (reportId === FIXTURE.report_id) return reportHash(FIXTURE);
  return registered.get(reportId)?.report_hash ?? null;
}

function explorer(tx: string | null) {
  return tx ? `https://sepolia.etherscan.io/tx/${tx}` : null;
}

/** GET /reports/{id}/verify, where the server holds the report. */
export async function verifyById(id: string): Promise<VerificationResult> {
  await wait(800);
  const report = await getReport(id);
  return buildResult(report, reportHash(report));
}

/** Upload path: hash the user's file locally, then ask the chain for the registered hash. */
export async function verifyUploaded(json: unknown): Promise<VerificationResult> {
  await wait(800);
  const report = json as AssessmentReport;
  if (!report || typeof report.report_id !== "string") {
    throw new ApiError("This file isn't a CyberMatrix report: no report_id field.");
  }
  return buildResult(report, reportHash(json));
}

function buildResult(report: AssessmentReport, computed: string): VerificationResult {
  const onchain = mockOnchainHash(report.report_id);
  const isFixture = report.report_id === FIXTURE.report_id;
  return {
    report_id: report.report_id,
    computed_hash: computed,
    onchain_hash: onchain,
    match: onchain !== null && onchain === computed,
    onchain_status: onchain ? (isFixture ? "validated" : "submitted") : null,
    onchain_created_at: onchain ? "2026-11-08T02:14:00Z" : null,
    tx_hash: onchain ? MOCK_TX : null,
    explorer_url: onchain ? explorer(MOCK_TX) : null,
    note: "A matching hash proves this report is unchanged since it was registered. It does not prove the report's conclusions are true.",
  };
}

export async function getClusters(): Promise<Cluster[]> {
  await wait(400);
  return MOCK_CLUSTERS;
}
