import DOMPurify from "isomorphic-dompurify";

/* ================================
 * Utilities
 * ================================ */

import type { YYYYMMDD } from "./types";

// utils/utilities.ts
export function arrayToBase64(data: Uint8Array): string {
  let binary = "";
  const bytes = data;
  const len = bytes.byteLength;

  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

export function base64ToUint8Array(base64: string): Uint8Array {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

export function base64ToUtf8(base64: string): string {
  const buf = base64ToArrayBuffer(base64);
  return new TextDecoder().decode(new Uint8Array(buf));
}

export function utf8ToBase64(str: string): string {
  const bytes = new TextEncoder().encode(str);
  return arrayBufferToBase64(bytes.buffer);
}

export function concatArrayBuffers(
  a: ArrayBuffer,
  b: ArrayBuffer,
): ArrayBuffer {
  const tmp = new Uint8Array(a.byteLength + b.byteLength);
  tmp.set(new Uint8Array(a), 0);
  tmp.set(new Uint8Array(b), a.byteLength);
  return tmp.buffer;
}

export function concatUint8Arrays(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.byteLength + b.byteLength);
  out.set(a, 0);
  out.set(b, a.byteLength);
  return out;
}

export interface MnemonicJSON {
  seed: string[];
  id: string;
  phrase?: string;
}

/**
 * Converts a space-separated seed phrase string into MnemonicJSON
 */
export function seedToJSON(
  seed: string,
  id: string,
  phrase?: string,
): MnemonicJSON {
  return {
    seed: seed
      .trim()
      .split(/\s+/)
      .map((w) => w.toLowerCase())
      .filter(Boolean),
    id,
    phrase,
  };
}

/**
 * Converts MnemonicJSON into a single space-separated string
 */
export function jsonToSeed(json: MnemonicJSON): string {
  return json.seed.join(" ");
}

export function seedStringToArray(seed: string): string[] {
  return seed
    .trim()
    .split(/\s+/)
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}

/**
 * Convert Date → YYYY-MM-DD (UTC-safe)
 */
export function dateToYYYYMMDD(date: Date): YYYYMMDD {
  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    throw new Error("Invalid Date object");
  }

  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");

  return `${y}-${m}-${d}` as YYYYMMDD;
}

/**
 * Convert YYYY-MM-DD → Date (UTC midnight)
 */
export function YYYYMMDDToDate(yyyymmdd: YYYYMMDD): Date {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(yyyymmdd)) {
    throw new Error("Invalid ISO date format. Expected YYYY-MM-DD");
  }

  const [year, month, day] = yyyymmdd.split("-").map(Number);

  const date = new Date(year, month - 1, day); // ✅ LOCAL midnight

  // Validation
  if (
    date.getFullYear() !== year ||
    date.getMonth() !== month - 1 ||
    date.getDate() !== day
  ) {
    throw new Error("Invalid calendar date");
  }

  return date;
}

export function stripUndefined<T extends Record<string, unknown>>(
  obj: T,
): Partial<T> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, value]) => value !== undefined),
  ) as Partial<T>;
}

/**
 * 1. Safe Reference Resolver
 */
const getSafeSanitizer = () => {
  try {
    const dp: any = DOMPurify;
    const sanitize = dp?.sanitize || dp?.default?.sanitize;
    if (typeof sanitize === "function") return sanitize;
  } catch (e) {
    console.warn(
      "MajikUser: DOMPurify failed to init. Using hardened fallback.",
    );
  }
  return null;
};

const internalSanitize = getSafeSanitizer();

/**
 * High-risk patterns for the fallback logic.
 * Covers tags, event handlers, and dangerous protocols.
 */
const DANGER_PATTERNS = [
  /<svg|<img|<script|<iframe|<object|<embed|<link|<meta|<style|<base/i,
  /onload=|onerror=|onclick=/i,
  /javascript:|data:/i,
  /<[^>]*>|&[#\w]+;/g, // General HTML tags and entities
];

/**
 * 2. The Fail-Proof Validator
 */
export function checkForHTMLTags(input: string): boolean {
  if (!input || typeof input !== "string" || !input.trim()) return false;

  // First line of defense: pattern matching (fast and reliable)
  const hasPatterns = DANGER_PATTERNS.some((pattern) => pattern.test(input));
  if (hasPatterns) return true;

  // Second line of defense: DOMPurify (if available)
  try {
    if (internalSanitize) {
      const clean = internalSanitize(input, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
      });
      return input.trim() !== clean.trim();
    }
  } catch (err) {
    console.warn("DOMPurify check failed, relying on pattern matching");
  }

  return false;
}

/**
 * 3. The Fail-Proof Sanitizer
 */
export function sanitizeInput(input: string): string {
  if (!input || typeof input !== "string") return "";

  try {
    if (internalSanitize) {
      return internalSanitize(input, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true,
      }).trim();
    }
  } catch (err) {
    // Hardened Fallback:
    // 1. Remove specific dangerous protocols/attributes first
    let hardened = input
      .replace(/javascript:/gi, "[removed]")
      .replace(/data:/gi, "[removed]") // Added this
      .replace(/onload=|onerror=|onclick=/gi, "prevented=");

    // 2. Strip all remaining HTML tags
    return hardened.replace(/<[^>]*>/g, "").trim();
  }

  return input.trim();
}
