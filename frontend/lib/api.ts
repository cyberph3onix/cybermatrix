/**
 * API client for the FastAPI backend (NEXT_PUBLIC_API_URL, default http://localhost:8000).
 * Request/response types come from the generated OpenAPI types in ./types.
 */
import type {
  AssessRequest,
  AssessResponse,
  AssessmentReport,
  Cluster,
  DisputePrepared,
  OwnershipChallenge,
  OwnershipGrant,
  RegistryRecord,
  ReportHistory,
  VerificationResult,
} from "./types";

const BASE = (process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000").replace(/\/$/, "");
// A full assessment fetches the page, scans TLS and queries threat-intel sources: allow up to ~1 minute.
const ASSESS_TIMEOUT_MS = 90_000;
const DEFAULT_TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

/** FastAPI errors are {detail: string} or, for 422s, {detail: [{msg, loc}]}. */
function detailOf(body: unknown, fallback: string): string {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const msg = (detail[0] as { msg?: unknown } | undefined)?.msg;
    if (typeof msg === "string") return msg;
  }
  return fallback;
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  let res: Response;
  try {
    res = await fetch(BASE + path, {
      cache: "no-store",
      ...init,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    const timedOut = e instanceof DOMException && e.name === "TimeoutError";
    throw new ApiError(
      timedOut
        ? "The server took too long to answer. Try again in a moment."
        : "Can't reach the CyberMatrix server. Check your connection and try again.",
    );
  }
  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detailOf(body, `Request failed (HTTP ${res.status}).`), res.status);
  }
  return (await res.json()) as T;
}

const json = (method: string, body?: unknown): RequestInit => ({
  method,
  headers: body === undefined ? undefined : { "Content-Type": "application/json" },
  body: body === undefined ? undefined : JSON.stringify(body),
});

export async function assess(req: AssessRequest): Promise<AssessResponse> {
  if (!req.input.trim()) throw new ApiError("Enter a link, domain, email or message.");
  return request("/assess", json("POST", req), ASSESS_TIMEOUT_MS);
}

export async function assessQr(file: File): Promise<AssessResponse> {
  if (!file.type.startsWith("image/")) throw new ApiError("Upload an image file (PNG or JPG).");
  const form = new FormData();
  form.append("file", file);
  return request("/assess/qr", { method: "POST", body: form }, ASSESS_TIMEOUT_MS);
}

export async function getReport(id: string): Promise<AssessmentReport> {
  return request(`/reports/${encodeURIComponent(id)}`);
}

/** The stored registry record, or null if this report has not been registered. */
export async function getRegistration(id: string): Promise<RegistryRecord | null> {
  return request(`/reports/${encodeURIComponent(id)}/registration`);
}

export async function registerReport(id: string): Promise<RegistryRecord> {
  // Waits for the transaction to be mined (up to ~3 minutes on Sepolia).
  return request(`/reports/${encodeURIComponent(id)}/register`, json("POST"), 200_000);
}

/** GET /reports/{id}/verify: the server holds the report. */
export async function verifyById(id: string): Promise<VerificationResult> {
  return request(`/reports/${encodeURIComponent(id)}/verify`, {}, 60_000);
}

/** Upload path: the server hashes the file exactly as verify/verify.py does and looks it up on-chain. */
export async function verifyUploaded(report: unknown): Promise<VerificationResult> {
  if (!report || typeof report !== "object" || typeof (report as { report_id?: unknown }).report_id !== "string") {
    throw new ApiError("This file isn't a CyberMatrix report: no report_id field.");
  }
  return request("/verify", json("POST", report), 60_000);
}

export async function getClusters(): Promise<Cluster[]> {
  return request("/clusters");
}

/** Versions (oldest first), on-chain statuses, open dispute and the bond needed to dispute. */
export async function getHistory(id: string): Promise<ReportHistory> {
  return request(`/reports/${encodeURIComponent(id)}/history`, {}, 60_000);
}

/** Stores the reason off-chain and returns the transaction the user's own wallet sends (with the bond). */
export async function prepareDispute(id: string, reason: string): Promise<DisputePrepared> {
  return request(`/reports/${encodeURIComponent(id)}/dispute-reason`, json("POST", { reason }), 60_000);
}

/** Assess the same link again and register it as a revision; the old version becomes Superseded. */
export async function reassessReport(id: string): Promise<AssessResponse> {
  return request(`/reports/${encodeURIComponent(id)}/reassess`, json("POST"), 290_000);
}

/** Start proving you own a site (needed before the /.env and /.git exposure check). */
export async function ownershipChallenge(target: string): Promise<OwnershipChallenge> {
  return request("/ownership/challenge", json("POST", { target }));
}

export async function ownershipVerify(challenge: string): Promise<OwnershipGrant> {
  return request("/ownership/verify", json("POST", { challenge }), 45_000);
}
