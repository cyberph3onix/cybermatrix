import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const plexSans = IBM_Plex_Sans({
  variable: "--font-plex-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});
const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500"],
});

export const metadata: Metadata = {
  title: "CyberMatrix",
  description:
    "Check a link, message or QR code against threat intelligence and technical evidence. Every finding shows its source.",
};

export const viewport: Viewport = { width: "device-width", initialScale: 1 };

const NAV = [
  { href: "/", label: "Investigate" },
  { href: "/verify", label: "Verify" },
  { href: "/clusters", label: "Clusters" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body className="min-h-dvh flex flex-col">
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
      </body>
    </html>
  );
}
