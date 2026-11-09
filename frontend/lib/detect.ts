import type { SubjectType } from "./types";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\.?(?::\d+)?(?:[/?#]\S*)?$/i;

/** Guess what the user pasted. Backend re-detects; this only drives the UI hint. */
export function detectSubjectType(raw: string): SubjectType | null {
  const text = raw.trim();
  if (!text) return null;
  if (/\s/.test(text)) return "message";
  if (EMAIL.test(text)) return "email";
  if (/^https?:\/\/\S+$/i.test(text)) return "url";
  if (DOMAIN.test(text)) {
    return /[/?#]/.test(text) ? "url" : "domain";
  }
  return "message";
}

export const SUBJECT_LABEL: Record<SubjectType, string> = {
  url: "Link",
  domain: "Domain",
  email: "Email address",
  message: "Message text",
  qr: "QR code",
};

/**
 * SEC-8: the pasted text looks like it contains the user's own secret (a password, PIN, wallet private key or
 * recovery phrase). We never ask for these; the investigate page warns so the user can remove it first.
 */
const SECRET_PATTERNS: RegExp[] = [
  /\b(?:my\s+)?(?:password|passcode|passwd|pwd|upi\s*pin|m-?pin|atm\s*pin|pin)\s*(?:is|[:=])\s*\S{3,}/i,
  /\b(?:seed|recovery|secret|mnemonic)\s*(?:phrase|words)?\s*[:=-]\s*(?:[a-z]{3,8}\s+){11,}[a-z]{3,8}\b/i,
  /\b(?:private\s*key|priv\s*key|secret\s*key)\s*[:=]?\s*(?:0x)?[0-9a-f]{64}\b/i,
  /(?:^|\s)(?:0x)?[0-9a-f]{64}(?:\s|$)/i,
];

export function looksLikeSecret(text: string): boolean {
  return SECRET_PATTERNS.some((rx) => rx.test(text));
}
