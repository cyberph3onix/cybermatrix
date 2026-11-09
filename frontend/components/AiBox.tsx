import type { AIExplanation } from "@/lib/types";

export function AiBox({ ai }: { ai: AIExplanation }) {
  return (
    <div className="rounded-md border border-rule bg-panel p-4">
      <p className="max-w-prose">{ai.summary}</p>
      {ai.injection_attempt_detected && (
        <p className="mt-3 rounded border border-amber-400 bg-amber-50 p-2 text-sm text-amber-950">
          The submitted text contained instructions aimed at an AI model. They were ignored.
        </p>
      )}
      {ai.verified_evidence_refs.length > 0 && (
        <p className="mt-3 text-sm text-muted">
          Based on findings:{" "}
          {ai.verified_evidence_refs.map((r) => (
            <code key={r} className="mr-2 inline-block font-mono text-xs text-ink">
              {r}
            </code>
          ))}
        </p>
      )}
      <p className="mt-3 border-t border-rule pt-3 text-sm text-muted">
        {ai.disclaimer} <span className="font-mono text-xs">({ai.model})</span>
      </p>
    </div>
  );
}
