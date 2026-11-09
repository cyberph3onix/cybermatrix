import type { RedirectHop } from "@/lib/types";

export function RedirectTimeline({ hops }: { hops: RedirectHop[] }) {
  if (hops.length === 0) {
    return <p className="text-sm text-muted">No redirects were followed.</p>;
  }
  return (
    <ol className="relative ml-2 border-l-2 border-rule">
      {hops.map((h, i) => {
        const last = i === hops.length - 1;
        return (
          <li key={i} className="relative pb-5 pl-6 last:pb-0">
            <span
              aria-hidden
              className={`absolute -left-[9px] top-1 h-4 w-4 rounded-full border-2 border-ink ${
                last ? "bg-ink" : "bg-panel"
              }`}
            />
            <p className="break-all font-mono text-sm">{h.url}</p>
            <p className="mt-0.5 text-xs text-muted">
              <span className="font-medium text-ink">
                {last ? "Final page" : `Hop ${i + 1}`}
              </span>
              {" · HTTP "}
              {h.status_code}
              {h.resolved_ip && <> · {h.resolved_ip}</>}
              {h.cross_domain && (
                <span className="ml-2 rounded border border-amber-400 bg-amber-50 px-1.5 py-0.5 text-amber-900">
                  Different domain
                </span>
              )}
            </p>
          </li>
        );
      })}
    </ol>
  );
}
