/**
 * Builds the visible investigation trace for a report: which questions were asked, in what order, which sources
 * answered, what each step found, and how the deterministic rules turned the findings into the verdict.
 *
 * Everything here is derived from the report itself (check_runs, findings, classification_reason), so the trace
 * shows exactly what produced the stored, hashed report. Steps whose evidence came from an AI model are marked
 * `ai`, because the AI only reads and extracts: the rules decide (CLAUDE.md rule 1).
 */
import type { AssessmentReport, CheckRun, Finding, Severity } from "./types";

export type StepStatus = "found" | "clear" | "partial" | "gap" | "skipped";

export interface TraceStep {
  key: string;
  question: string;
  how: string;
  ai: boolean;
  runs: CheckRun[];
  findings: Finding[];
  status: StepStatus;
  worst: Severity | null;
}

export interface TraceVerdict {
  rule: string;
  ruleText: string;
  triggers: Finding[];
  score: number;
  coverage: number;
  heuristicCapped: boolean;
  postureCount: number;
}

interface StepDef {
  key: string;
  question: string;
  how: string;
  ai?: boolean;
  groups: string[];
  match: (f: Finding, aiEvidence: boolean) => boolean;
}

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const fromAi = (f: Finding) => f.evidence.some((e) => e.source.startsWith("llm:"));
const id = (f: Finding) => f.check_id;

const LINK_STEPS: StepDef[] = [
  {
    key: "address",
    question: "Is the address itself deceptive?",
    how: "Parsed the link and compared its domain with known brands: look-alike letters, typos, brand names in subdomains, hidden destinations.",
    groups: ["url.structure", "url.lookalike"],
    match: (f) => id(f).startsWith("URL.") && !id(f).startsWith("URL.INTEL."),
  },
  {
    key: "reputation",
    question: "Do threat-intelligence services already know it?",
    how: "Looked the link (and every redirect destination) up in Google Safe Browsing, URLhaus, OpenPhish and VirusTotal.",
    groups: ["intel.gsb", "intel.urlhaus", "intel.openphish", "intel.virustotal"],
    match: (f) => id(f).startsWith("URL.INTEL."),
  },
  {
    key: "redirects",
    question: "Where does the link really lead?",
    how: "Followed every redirect ourselves (no JavaScript), re-checking each hop's address before connecting.",
    groups: ["fetch.redirects"],
    match: (f) => id(f).startsWith("REDIRECT."),
  },
  {
    key: "domain",
    question: "Who registered the domain, and when?",
    how: "Read the domain's registration record (RDAP) and its DNS setup.",
    groups: ["domain.rdap", "domain.dns"],
    match: (f) => id(f).startsWith("DOMAIN."),
  },
  {
    key: "certificate",
    question: "Can its certificate be trusted?",
    how: "Validated the TLS chain against several root stores and our list of distrusted CAs, checked revocation, and read Certificate Transparency logs.",
    groups: ["tls.chain", "tls.revocation", "tls.ct"],
    match: (f) => id(f).startsWith("TLS."),
  },
  {
    key: "page",
    question: "What does the page ask visitors for?",
    how: "Read the page's HTML: password and card fields, where forms send data, and which brand the page names.",
    groups: ["page.content"],
    match: (f, ai) => id(f).startsWith("PAGE.") && !ai,
  },
  {
    key: "ai-page",
    question: "Which organisation does the page present itself as?",
    how: "An AI model read the page text (and the screenshot, if one was added) and reported the brand shown. Code then compared that brand with the real domain.",
    ai: true,
    groups: ["page.llm", "page.screenshot"],
    match: (f, ai) => id(f).startsWith("PAGE.") && ai,
  },
];

const MESSAGE_STEPS: StepDef[] = [
  {
    key: "message",
    question: "What does the message say, and what does it ask for?",
    how: "Masked personal details, then looked for requests for OTPs, PINs or payment, impersonated organisations, and (for emails) sender authentication.",
    groups: ["message.extract"],
    match: (f, ai) => id(f).startsWith("MSG.") && !ai,
  },
  {
    key: "ai-message",
    question: "How does the wording read: urgency, pressure, lures?",
    how: "An AI model read the masked message and pointed out language signals. They count as heuristic evidence only.",
    ai: true,
    groups: ["message.signals"],
    match: (f, ai) => id(f).startsWith("MSG.") && ai,
  },
  {
    key: "links",
    question: "Are the links in it dangerous?",
    how: "Every link in the message got the full link investigation: address, reputation, redirects, certificate and page.",
    groups: ["message.urls"],
    match: (f) => !id(f).startsWith("MSG.") && !id(f).startsWith("CORR."),
  },
];

const UPI_STEPS: StepDef[] = [
  {
    key: "upi",
    question: "Who is the payment request for?",
    how: "Decoded the payment QR and kept only the payee ID. There is no website behind a UPI request to inspect.",
    groups: ["upi.payee"],
    match: () => false,
  },
];

const HISTORY: StepDef = {
  key: "history",
  question: "Have we seen it before?",
  how: "Compared its domain, contact details and infrastructure with earlier reports on this server, including reports validated on-chain.",
  groups: [],
  match: (f) => id(f).startsWith("CORR."),
};

export const RULE_TEXT: Record<string, string> = {
  R1: "An authoritative source reported a critical match (for example a threat-intelligence listing).",
  R1b: "Corroborated impersonation: a look-alike address, a credential form and a freshly created domain or certificate together.",
  R2: "A critical technical finding, at least two high technical findings, or a total score of 60 or more.",
  R3: "At least one finding of medium severity or above, or a total score of 20 or more.",
  R4: "Less than half of the checks could run, so there is too little to judge.",
  R5: "No significant malicious indicators within the checks that ran.",
};

function statusOf(runs: CheckRun[], findings: Finding[]): StepStatus {
  if (findings.length) return "found";
  if (runs.length === 0) return "clear"; // history: correlation always runs on this server
  const done = runs.filter((r) => r.status === "completed").length;
  if (runs.every((r) => r.status === "skipped")) return "skipped";
  if (done === 0) return "gap";
  return runs.some((r) => r.status === "unavailable" || r.status === "failed") ? "partial" : "clear";
}

function worst(fs: Finding[]): Severity | null {
  return fs.reduce<Severity | null>((w, f) => (w === null || RANK[f.severity] > RANK[w] ? f.severity : w), null);
}

export function buildTrace(report: AssessmentReport): TraceStep[] {
  const defs =
    report.subject_type === "message" || report.subject_type === "email"
      ? report.check_runs.some((r) => r.check_group.startsWith("message."))
        ? MESSAGE_STEPS
        : LINK_STEPS // an email address is assessed through its domain
      : report.check_runs.some((r) => r.check_group === "upi.payee")
        ? UPI_STEPS
        : LINK_STEPS;
  const used = new Set<Finding>();
  const byGroup = (g: string[]) => report.check_runs.filter((r) => g.includes(r.check_group));
  const steps: TraceStep[] = [];
  for (const d of [...defs, HISTORY]) {
    const findings = report.findings.filter((f) => !used.has(f) && d.match(f, fromAi(f)));
    findings.forEach((f) => used.add(f));
    const runs = byGroup(d.groups);
    if (d.key !== "history" && runs.length === 0 && findings.length === 0) continue;
    steps.push({ key: d.key, question: d.question, how: d.how, ai: !!d.ai, runs, findings,
                 status: statusOf(runs, findings), worst: worst(findings) });
  }
  const rest = report.findings.filter((f) => !used.has(f));
  if (rest.length) {
    steps.splice(steps.length - 1, 0, { key: "other", question: "Other signals", how: "Further checks that fired.",
      ai: rest.some(fromAi), runs: [], findings: rest, status: "found", worst: worst(rest) });
  }
  return steps;
}

export function buildVerdict(report: AssessmentReport): TraceVerdict {
  const m = /^(R\d+b?)/.exec(report.classification_reason);
  const rule = m ? m[1] : "";
  const after = report.classification_reason.split(":").slice(1).join(":");
  const ids = new Set(after.split("+").map((s) => s.trim()).filter((s) => /^[A-Z]+\.[A-Z0-9_.]+$/.test(s)));
  return {
    rule,
    ruleText: RULE_TEXT[rule] ?? report.classification_reason,
    triggers: report.findings.filter((f) => ids.has(f.check_id)),
    score: report.score,
    coverage: report.coverage.percent,
    heuristicCapped: report.findings.some((f) => f.strength === "heuristic"),
    postureCount: report.security_posture.length,
  };
}
