import { CATEGORY_LABEL } from "@/lib/classes";
import type { Finding, FindingCategory } from "@/lib/types";
import { FindingCard } from "./FindingCard";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;

export function FindingGroups({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="rounded-md border border-rule bg-panel p-4 text-sm">
        No findings were produced by the checks that ran. That does not prove the subject is
        trustworthy. See the limitations below.
      </p>
    );
  }
  const groups = new Map<FindingCategory, Finding[]>();
  for (const f of findings) groups.set(f.category, [...(groups.get(f.category) ?? []), f]);
  const ordered = [...groups.entries()]
    .map(([cat, list]) => [cat, [...list].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])] as const)
    .sort((a, b) => SEV_ORDER[a[1][0].severity] - SEV_ORDER[b[1][0].severity]);

  return (
    <div className="space-y-6">
      {ordered.map(([cat, list]) => (
        <div key={cat}>
          <h3 className="mb-2 text-base font-semibold">
            {CATEGORY_LABEL[cat] ?? cat}{" "}
            <span className="font-normal text-muted">({list.length})</span>
          </h3>
          <ul className="space-y-2">
            {list.map((f) => (
              <FindingCard key={f.check_id + (f.indicator_ref ?? "")} finding={f} />
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
