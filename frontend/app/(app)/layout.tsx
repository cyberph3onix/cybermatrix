import Link from "next/link";

const NAV = [
  { href: "/investigate", label: "Investigate" },
  { href: "/verify", label: "Verify" },
  { href: "/clusters", label: "Clusters" },
  { href: "/watch", label: "CT watch" },
  { href: "/org", label: "Organisation" },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col">
      <header className="border-b border-rule bg-panel">
        <div className="mx-auto flex max-w-4xl flex-wrap items-center justify-between gap-x-6 gap-y-1 px-4 py-3">
          <Link href="/" className="text-lg font-semibold tracking-tight">
            CyberMatrix
          </Link>
          <nav aria-label="Main" className="flex gap-1 text-sm">
            {NAV.map((n) => (
              <Link
                key={n.href}
                href={n.href}
                className="inline-flex min-h-11 items-center rounded px-3 text-muted hover:bg-paper hover:text-ink"
              >
                {n.label}
              </Link>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-4xl flex-1 px-4 py-8">{children}</main>
      <footer className="border-t border-rule bg-panel">
        <p className="mx-auto max-w-4xl px-4 py-4 text-sm text-muted">
          Results describe the checks that ran. No result is a guarantee that a link, message or
          site is trustworthy.
        </p>
      </footer>
    </div>
  );
}
