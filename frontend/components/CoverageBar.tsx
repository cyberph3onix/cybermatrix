import { CHECK_GROUP_LABEL } from "@/lib/classes";
import type { AssessmentReport } from "@/lib/types";

type Seg = { group: string; state: "completed" | "unavailable" | "failed" | "skipped" };

const STATE: Record<Seg["state"], { label: string; cls: string }> = {
  completed: { label: "Ran", cls: "bg-ink" },
  unavailable: { label: "Unavailable", cls: "bg-white border border-ink border-dashed" },
  failed: { label: "Failed", cls: "bg-white border border-ink" },
  skipped: { label: "Not applicable", cls: "bg-black/10" },
};

/** One segment per check group, so a gap is visible rather than averaged away. */
export function CoverageBar({ report }: { report: AssessmentReport }) {
  const c = report.coverage;
  const segs: Seg[] = [
    ...c.completed.map((group) => ({ group, state: "completed" as const })),
    ...c.unavailable.map((group) => ({ group, state: "unavailable" as const })),
    ...c.failed.map((group) => ({ group, state: "failed" as const })),
    ...c.skipped.map((group) => ({ group, state: "skipped" as const })),
  ];
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className="font-medium">Coverage</span>
        <span className="tabular-nums">
          {c.percent}% of weighted checks ran
        </span>
      </div>
      <ul
        className="fill-in mt-1.5 flex gap-1"
        aria-label={`Coverage: ${c.percent} percent. ${c.completed.length} checks ran, ${c.unavailable.length} unavailable, ${c.failed.length} failed.`}
      >
        {segs.map((s) => (
          <li
            key={s.group}
            className={`h-3 flex-1 rounded-sm ${STATE[s.state].cls}`}
            title={`${CHECK_GROUP_LABEL[s.group] ?? s.group}: ${STATE[s.state].label}`}
          />
        ))}
      </ul>
      <p className="mt-1.5 text-sm">
        {c.completed.length} ran
        {c.unavailable.length > 0 && <>, {c.unavailable.length} unavailable ({names(c.unavailable)})</>}
        {c.failed.length > 0 && <>, {c.failed.length} failed ({names(c.failed)})</>}
        {c.skipped.length > 0 && <>, {c.skipped.length} not applicable</>}.
      </p>
    </div>
  );
}

function names(groups: string[]) {
  return groups.map((g) => CHECK_GROUP_LABEL[g] ?? g).join(", ");
}
