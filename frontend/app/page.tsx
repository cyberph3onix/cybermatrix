"use client";

import { useRouter } from "next/navigation";
import { useMemo, useRef, useState } from "react";
import { assess, assessQr } from "@/lib/api";
import { detectSubjectType, SUBJECT_LABEL } from "@/lib/detect";

export default function Home() {
  const router = useRouter();
  const [text, setText] = useState("");
  const [qr, setQr] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const detected = useMemo(() => (qr ? "qr" : detectSubjectType(text)), [qr, text]);
  const canSubmit = !busy && (qr !== null || text.trim().length > 0);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setErr(null);
    try {
      const { report_id } = qr
        ? await assessQr(qr)
        : await assess({ input: text, subject_type: detected });
      router.push(`/report/${report_id}`);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Something went wrong. Try again.");
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="text-3xl font-semibold leading-tight sm:text-4xl">
        Check a link, message or QR code before you act on it
      </h1>
      <p className="mt-3 max-w-prose text-muted">
        Paste what you received. We run technical checks and threat-intelligence lookups, then show
        each finding with its evidence and where it came from.
      </p>

      <form onSubmit={submit} className="mt-8 space-y-3">
        <label htmlFor="subject" className="block font-medium">
          Link, domain, email address or message
        </label>
        <textarea
          id="subject"
          rows={4}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            if (qr) setQr(null);
          }}
          placeholder="https://example.com/login   or   “Your account is blocked, update KYC at…”"
          className="block w-full resize-y rounded-md border border-rule bg-panel p-3 text-base shadow-sm placeholder:text-slate-400"
          maxLength={20000}
          autoComplete="off"
          spellCheck={false}
        />

        <p className="min-h-6 text-sm text-muted" aria-live="polite">
          {detected ? (
            <>
              Treating this as: <span className="font-medium text-ink">{SUBJECT_LABEL[detected]}</span>
              {detected === "message" && ". Phone numbers, emails, account numbers and OTP-like digits are masked before analysis."}
            </>
          ) : (
            "Nothing is sent until you press Investigate."
          )}
        </p>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={!canSubmit}
            className="min-h-11 rounded bg-accent px-5 py-2 font-medium text-white hover:bg-[#163f64] disabled:opacity-50"
          >
            {busy ? "Investigating…" : "Investigate"}
          </button>

          <input
            ref={fileRef}
            type="file"
            accept="image/*"
            className="sr-only"
            id="qr"
            onChange={(e) => {
              const f = e.target.files?.[0] ?? null;
              setQr(f);
              if (f) setText("");
            }}
          />
          <label
            htmlFor="qr"
            className="inline-flex min-h-11 cursor-pointer items-center rounded border border-ink bg-panel px-4 py-2 text-sm font-medium hover:bg-paper has-[:focus-visible]:outline"
          >
            Upload QR image
          </label>
          {qr && (
            <span className="flex min-w-0 items-center gap-2 text-sm">
              <span className="truncate">{qr.name}</span>
              <button
                type="button"
                className="rounded px-2 py-1 text-accent underline"
                onClick={() => {
                  setQr(null);
                  if (fileRef.current) fileRef.current.value = "";
                }}
              >
                Remove
              </button>
            </span>
          )}
        </div>

        {err && (
          <p role="alert" className="rounded border border-c-mal bg-c-mal-tint p-3 text-sm text-c-mal-ink">
            {err}
          </p>
        )}
      </form>

      <section aria-labelledby="how" className="mt-12 border-t border-rule pt-6">
        <h2 id="how" className="text-lg font-semibold">
          What this does and doesn&apos;t do
        </h2>
        <ul className="mt-2 max-w-prose list-disc space-y-1.5 pl-5 text-sm text-muted">
          <li>Inspection is passive. We fetch the page safely and never run its scripts.</li>
          <li>Rules decide the risk class. The AI only explains the findings in plain language.</li>
          <li>The best result is &ldquo;low risk&rdquo;, always shown with what was and wasn&apos;t checked.</li>
        </ul>
        <p className="mt-4 text-sm">
          Want to see the five result types?{" "}
          {(["low_risk", "suspicious", "high_risk", "confirmed_malicious", "inconclusive"] as const).map((c, i) => (
            <span key={c}>
              {i > 0 && ", "}
              <a className="text-accent underline" href={`/report/demo-${c}`}>
                {c.replace("_", " ")}
              </a>
            </span>
          ))}
          .
        </p>
      </section>
    </div>
  );
}
