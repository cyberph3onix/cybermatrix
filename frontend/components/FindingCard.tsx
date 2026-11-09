import type { Finding } from "@/lib/types";
import { SeverityBadge, StrengthBadge } from "./Badges";

function fmtData(data: Record<string, unknown>) {
  return Object.entries(data).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : String(v)] as const);
}

export function FindingCard({ finding: f }: { finding: Finding }) {
  return (
    <li id={`finding-${f.check_id}`} className="scroll-mt-4 rounded-md border border-rule bg-panel">
      <details className="group">
        <summary className="flex cursor-pointer list-none items-start gap-3 p-3 sm:p-4">
          <svg
            aria-hidden
            width="16"
            height="16"
            viewBox="0 0 16 16"
            className="mt-1 shrink-0 text-muted transition-transform group-open:rotate-90"
          >
            <path d="m6 3 5 5-5 5" fill="none" stroke="currentColor" strokeWidth="2" />
          </svg>
          <div className="min-w-0 flex-1">
            <p className="font-medium">{f.title}</p>
            <div className="mt-1.5 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={f.severity} />
              <StrengthBadge strength={f.strength} />
              <code className="break-all font-mono text-xs text-muted">{f.check_id}</code>
            </div>
          </div>
        </summary>

        <div className="space-y-4 border-t border-rule p-3 text-sm sm:p-4 sm:pl-10">
          <p>
            <span className="font-medium">Why it matters: </span>
            {f.impact}
          </p>
          <p>
            <span className="font-medium">What to do: </span>
            {f.recommendation}
          </p>

          <div>
            <h4 className="font-medium">
              Evidence ({f.evidence.length})
            </h4>
            <ul className="mt-2 space-y-3">
              {f.evidence.map((e, i) => (
                <li key={i} className="rounded border border-rule bg-paper p-3">
                  <p>{e.description}</p>
                  {Object.keys(e.data).length > 0 && (
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs">
                      {fmtData(e.data).map(([k, v]) => (
                        <div key={k} className="contents">
                          <dt className="text-muted">{k}</dt>
                          <dd className="break-all">{v}</dd>
                        </div>
                      ))}
                    </dl>
                  )}
                  <p className="mt-2 text-xs text-muted">
                    Source: <span className="font-mono text-ink">{e.source}</span>
                    {" · "}
                    <span className="font-mono">{e.kind}</span>
                    {" · "}
                    <time dateTime={e.observed_at}>
                      {new Date(e.observed_at).toLocaleString(undefined, {
                        dateStyle: "medium",
                        timeStyle: "short",
                      })}
                    </time>
                  </p>
                </li>
              ))}
            </ul>
          </div>

          <p className="rounded border border-rule bg-paper p-3">
            <span className="font-medium">Limitation: </span>
            {f.limitation ?? "None recorded for this finding."}
          </p>
        </div>
      </details>
    </li>
  );
}
