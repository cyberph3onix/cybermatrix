import { SEVERITY_STYLE, STRENGTH_INFO } from "@/lib/classes";
import type { EvidenceStrength, Severity } from "@/lib/types";

const chip = "inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium";

export function StrengthBadge({ strength }: { strength: EvidenceStrength }) {
  const s = STRENGTH_INFO[strength];
  return (
    <span className={`${chip} ${s.cls}`} title={s.blurb}>
      {s.label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLE[severity];
  return <span className={`${chip} ${s.cls}`}>{s.label}</span>;
}

export function StrengthLegend() {
  return (
    <dl className="grid gap-2 text-sm sm:grid-cols-3">
      {(Object.keys(STRENGTH_INFO) as EvidenceStrength[]).map((k) => (
        <div key={k} className="space-y-1">
          <dt>
            <StrengthBadge strength={k} />
          </dt>
          <dd className="text-muted">{STRENGTH_INFO[k].blurb}</dd>
        </div>
      ))}
    </dl>
  );
}
