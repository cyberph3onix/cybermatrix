import { keccak256 } from "js-sha3";

/**
 * RFC 8785 canonical JSON. The schema has no floats, so this reduces to
 * sorted object keys + JSON string escaping (identical to ES JSON.stringify
 * for strings and integers). Keys sort by UTF-16 code unit, as the RFC says,
 * which is JS's default string comparison.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error("Reports must not contain floating-point numbers.");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return (
      "{" +
      keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") +
      "}"
    );
  }
  throw new Error("Unsupported value in report JSON.");
}

/** 0x-prefixed keccak256 of the canonical report bytes. */
export function reportHash(report: unknown): string {
  return "0x" + keccak256(new TextEncoder().encode(canonicalize(report)));
}
