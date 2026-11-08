import { CLASS_STYLE, CONFIDENCE_LABEL } from "@/lib/classes";
import type { AssessmentReport } from "@/lib/types";
import { CoverageBar } from "./CoverageBar";

function Glyph({ kind, className }: { kind: string; className: string }) {
  const common = { width: 36, height: 36, viewBox: "0 0 36 36", "aria-hidden": true, className } as const;
  switch (kind) {
    case "ring":
      return (
        <svg {...common} fill="none" stroke="currentColor" strokeWidth="3">
          <circle cx="18" cy="18" r="13" />
        </svg>
      );
    case "triangle":
      return (
        <svg {...common} fill="none" stroke="currentColor" strokeWidth="3" strokeLinejoin="round">
          <path d="M18 5 33 31H3z" />
          <path d="M18 14v8M18 26.5v.5" strokeLinecap="round" />
        </svg>
      );
    case "octagon":
      return (
        <svg {...common} fill="currentColor">
          <path d="M11 3h14l8 8v14l-8 8H11l-8-8V11z" />
          <path d="M18 10v10M18 24v2" stroke="#fff" strokeWidth="3" strokeLinecap="round" />
        </svg>
      );
    case "cross":
      return (
        <svg {...common} fill="currentColor">
          <path d="M11 3h14l8 8v14l-8 8H11l-8-8V11z" />
          <path d="m12 12 12 12M24 12 12 24" stroke="#fff" strokeWidth="3.5" strokeLinecap="round" />
        </svg>
      );
    default:
      return (
        <svg {...common} fill="none" stroke="currentColor" strokeWidth="3" strokeDasharray="4 4">
          <circle cx="18" cy="18" r="13" />
        </svg>
      );
  }
}

export function ClassBanner({ report }: { report: AssessmentReport }) {
  const s = CLASS_STYLE[report.classification];
  const when = new Date(report.created_at).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
  return (
    <section
      aria-labelledby="verdict"
      className={`overflow-hidden rounded-md border ${s.border} ${s.tint} ${s.text}`}
    >
      <div className="flex">
        <div className={`w-2 shrink-0 ${s.bar}`} aria-hidden />
        <div className="min-w-0 flex-1 p-4 sm:p-6">
          <div className="flex items-start gap-3">
            <Glyph kind={s.glyph} className="mt-1 shrink-0" />
            <div className="min-w-0">
              <h1 id="verdict" className="text-3xl font-semibold leading-tight sm:text-4xl">
                {s.label}
              </h1>
              <p className="mt-1 max-w-prose">{s.headline}</p>
            </div>
          </div>

          <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-3">
            <div>
              <dt className="text-sm">Risk score</dt>
              <dd className="text-2xl font-semibold tabular-nums">
                {report.score}
                <span className="text-base font-normal"> / 100</span>
              </dd>
            </div>
            <div>
              <dt className="text-sm">Confidence</dt>
              <dd className="text-2xl font-semibold">{CONFIDENCE_LABEL[report.confidence]}</dd>
            </div>
            <div className="col-span-2 sm:col-span-1">
              <dt className="text-sm">Checked</dt>
              <dd className="text-base font-medium">{when}</dd>
            </div>
          </dl>

          <div className="mt-5">
            <CoverageBar report={report} />
          </div>

          <p className="mt-4 break-words text-sm">
            <span className="font-medium">Why this class: </span>
            <span className="font-mono text-[13px]">{report.classification_reason}</span>
          </p>
        </div>
      </div>
    </section>
  );
}
