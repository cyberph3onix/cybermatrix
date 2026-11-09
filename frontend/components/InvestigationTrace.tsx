import { CHECK_GROUP_LABEL, CLASS_STYLE, CONFIDENCE_LABEL } from "@/lib/classes";
import { buildTrace, buildVerdict, type StepStatus, type TraceStep } from "@/lib/investigation";
import type { AssessmentReport, CheckRun, Finding } from "@/lib/types";
import { SeverityBadge } from "./Badges";

const STATUS: Record<StepStatus, { label: string; cls: string }> = {
  found: { label: "Found something", cls: "border-c-high bg-c-high-tint text-c-high-ink" },
  clear: { label: "Nothing found", cls: "border-c-low bg-c-low-tint text-c-low-ink" },
  partial: { label: "Partly checked", cls: "border-c-inc bg-c-inc-tint text-c-inc-ink" },
  gap: { label: "Couldn't check", cls: "border-c-inc bg-c-inc-tint text-c-inc-ink" },
  skipped: { label: "Not needed", cls: "border-rule bg-paper text-muted" },
};

const RUN_MARK: Record<string, string> = { completed: "✓", unavailable: "–", failed: "✕", skipped: "·" };

function openFinding(checkId: string) {
  const el = document.getElementById(`finding-${checkId}`);
  el?.querySelector("details")?.setAttribute("open", "");
  el?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function FindingRef({ f }: { f: Finding }) {
  const ev = f.evidence[0];
  return (
    <li className="rounded border border-rule bg-paper p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={f.severity} />
        <button type="button" onClick={() => openFinding(f.check_id)} className="text-left font-medium underline-offset-2 hover:underline">
          {f.title}
        </button>
      </div>
      {ev && (
        <p className="mt-1 text-xs text-muted">
          {ev.description} <span className="font-mono text-ink">({ev.source})</span>
        </p>
      )}
    </li>
  );
}

function Sources({ runs }: { runs: CheckRun[] }) {
  if (!runs.length) return null;
  return (
    <ul className="mt-2 flex flex-wrap gap-1.5 text-xs" aria-label="Sources consulted">
      {runs.map((r) => (
        <li
          key={r.check_group}
          title={r.detail ?? undefined}
          className={`rounded border px-1.5 py-0.5 ${r.status === "completed" ? "border-rule bg-panel" : "border-dashed border-muted text-muted"}`}
        >
          <span aria-hidden>{RUN_MARK[r.status] ?? "·"} </span>
          {CHECK_GROUP_LABEL[r.check_group] ?? r.check_group}
          <span className="text-muted">
            {" · "}
            {r.status === "completed" ? `${r.duration_ms} ms` : r.status}
          </span>
          {r.status !== "completed" && r.status !== "skipped" && r.detail && (
            <span className="block max-w-[40ch] truncate text-muted">{r.detail}</span>
          )}
        </li>
      ))}
    </ul>
  );
}

function Step({ n, s }: { n: number; s: TraceStep }) {
  const st = STATUS[s.status];
  return (
    <li className="relative pb-6 pl-10 last:pb-0">
      <span aria-hidden className="absolute bottom-0 left-[13px] top-7 w-px bg-rule" />
      <span
        aria-hidden
        className={`absolute left-0 top-0 flex size-7 items-center justify-center rounded-full border text-xs font-semibold ${
          s.status === "found" ? "border-c-high bg-c-high-tint text-c-high-ink" : "border-rule bg-panel"
        }`}
      >
        {n}
      </span>
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-semibold">{s.question}</h3>
        {s.ai && (
          <span className="rounded border border-dashed border-accent px-1.5 py-0.5 text-xs font-medium text-accent">
            AI reading
          </span>
        )}
        <span className={`rounded border px-1.5 py-0.5 text-xs font-medium ${st.cls}`}>
          {s.status === "found" ? `${s.findings.length} finding${s.findings.length === 1 ? "" : "s"}` : st.label}
        </span>
      </div>
      <p className="mt-1 max-w-prose text-sm text-muted">{s.how}</p>
      <Sources runs={s.runs} />
      {s.findings.length > 0 && (
        <ul className="mt-2 space-y-1.5 text-sm">
          {s.findings.map((f, i) => (
            <FindingRef key={`${f.check_id}-${i}`} f={f} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function InvestigationTrace({ report }: { report: AssessmentReport }) {
  const steps = buildTrace(report);
  const v = buildVerdict(report);
  const style = CLASS_STYLE[report.classification];
  const total = report.check_runs.reduce((m, r) => Math.max(m, r.duration_ms), 0);
  const asked = new Set(report.check_runs.filter((r) => r.status === "completed").map((r) => r.check_group)).size;

  return (
    <div>
      <p className="mb-5 text-sm text-muted">
        {steps.length} questions · {asked} sources answered · ran in parallel, longest took {(total / 1000).toFixed(1)} s
      </p>
      <ol>
        {steps.map((s, i) => (
          <Step key={s.key} n={i + 1} s={s} />
        ))}
        <li className="relative pl-10">
          <span
            aria-hidden
            className={`absolute left-0 top-0 flex size-7 items-center justify-center rounded-full border-2 text-xs font-bold ${style.border} ${style.tint} ${style.text}`}
          >
            =
          </span>
          <div className={`rounded-md border-2 p-3 sm:p-4 ${style.border} ${style.tint}`}>
            <h3 className={`font-semibold ${style.text}`}>
              Verdict: {style.label}
              {v.rule && <span className="ml-2 font-mono text-sm">rule {v.rule}</span>}
            </h3>
            <p className="mt-1 text-sm">{v.ruleText}</p>
            {v.triggers.length > 0 && (
              <p className="mt-2 text-sm">
                Decided by:{" "}
                {v.triggers.map((f, i) => (
                  <span key={f.check_id}>
                    {i > 0 && " + "}
                    <button type="button" onClick={() => openFinding(f.check_id)} className="font-medium underline">
                      {f.title}
                    </button>
                  </span>
                ))}
              </p>
            )}
            <p className="mt-2 text-xs text-muted">
              Score {v.score}/100 · {v.coverage}% of checks completed · confidence{" "}
              {CONFIDENCE_LABEL[report.confidence].toLowerCase()}
            </p>
            <ul className="mt-2 list-disc space-y-0.5 pl-5 text-xs text-muted">
              <li>The verdict comes from fixed, published rules applied to the findings above, not from the AI.</li>
              {v.heuristicCapped && (
                <li>Heuristic signals (including AI readings) add at most 30 points and can&apos;t make a report high risk on their own.</li>
              )}
              {v.postureCount > 0 && (
                <li>{v.postureCount} security-posture item{v.postureCount === 1 ? "" : "s"} (such as missing headers) are listed separately and don&apos;t affect the verdict.</li>
              )}
              {report.ai && <li>The plain-language explanation was written by an AI after the verdict, from these findings only.</li>}
            </ul>
          </div>
        </li>
      </ol>
    </div>
  );
}
