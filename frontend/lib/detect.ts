import type { SubjectType } from "./types";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:[/?#]\S*)?$/i;

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
