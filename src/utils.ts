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

// ... arrayToBase64, base64ToUint8Array, arrayBufferToBase64, base64ToArrayBuffer,
//     base64ToUtf8, utf8ToBase64, concatArrayBuffers, concatUint8Arrays,
//     seedToJSON, jsonToSeed, seedStringToArray, dateToYYYYMMDD, YYYYMMDDToDate,
//     stripUndefined — ALL UNCHANGED, keep as-is.

/* ================================
 * Optional Sanitizer (isomorphic-dompurify)
 * ================================
 * isomorphic-dompurify is an OPTIONAL peer dependency — it is NOT installed
 * automatically and is NOT safe in every runtime (DOMPurify needs a real DOM,
 * which doesn't exist in edge/isolate runtimes like Cloudflare Workers:
 * see https://github.com/cure53/DOMPurify/issues/577).
 *
 * If it's installed and loadable here, MajikUser uses it for real
 * parser-based HTML/XSS sanitization. If it's missing, or fails to load,
 * MajikUser falls back to a regex-based sanitizer and logs one warning —
 * it never throws.
 */

type SanitizeFn = (input: string, config?: Record<string, unknown>) => string;

let sanitizerFn: SanitizeFn | null = null;
let sanitizerChecked = false;
let sanitizerLoadingPromise: Promise<void> | null = null;

// Kept in a variable (not a string literal directly in `import(...)`) so
// bundlers like esbuild (which Wrangler uses) don't try to statically
// resolve/inline it and hard-fail the build when it's absent. This keeps
// resolution deferred to runtime, where we can actually catch failure.
const OPTIONAL_SANITIZER_PKG = "isomorphic-dompurify";

async function loadOptionalSanitizer(): Promise<void> {
  try {
    const mod: any = await import(
      /* webpackIgnore: true */
      /* @vite-ignore */
      OPTIONAL_SANITIZER_PKG
    );
    const dp = mod?.default ?? mod;
    const fn = dp?.sanitize ?? dp?.default?.sanitize;

    if (typeof fn !== "function") {
      throw new Error(
        "isomorphic-dompurify loaded but sanitize() was not found",
      );
    }
    sanitizerFn = fn.bind(dp);
  } catch {
    sanitizerFn = null;
    console.warn(
      "[MajikUser] 'isomorphic-dompurify' is not installed or failed to load in this runtime. " +
        "Falling back to the built-in regex-based sanitizer (weaker against sophisticated " +
        "HTML/XSS payloads). To enable full DOMPurify sanitization, install it in your project:\n" +
        "  npm install isomorphic-dompurify\n" +
        "Note: it requires a real DOM and currently does not work in edge/isolate runtimes " +
        "such as Cloudflare Workers.",
    );
  } finally {
    sanitizerChecked = true;
  }
}

function ensureSanitizerLoading(): Promise<void> {
  if (!sanitizerLoadingPromise) {
    sanitizerLoadingPromise = loadOptionalSanitizer();
  }
  return sanitizerLoadingPromise;
}

/**
 * Optional: call and `await` this once at app/worker startup so the real
 * sanitizer (if installed) is ready before the first request, avoiding a
 * fallback on cold start. Returns true if DOMPurify is active.
 *
 * Cloudflare Worker example:
 *   let ready: Promise<boolean> | null = null;
 *   export default {
 *     async fetch(req, env, ctx) {
 *       ready ??= preloadMajikSanitizer();
 *       await ready;
 *       ...
 *     }
 *   }
 */
export async function preloadMajikSanitizer(): Promise<boolean> {
  await ensureSanitizerLoading();
  return sanitizerFn !== null;
}

// Fire-and-forget kick-off, so later (not the very first) sync calls in the
// same process can benefit once the async load resolves.
function kickOffLazyLoad(): void {
  if (!sanitizerChecked && !sanitizerLoadingPromise) {
    void ensureSanitizerLoading();
  }
}

function regexCheckForHTMLTags(input: string): boolean {
  return DANGER_PATTERNS.some((pattern) => pattern.test(input));
}

function regexSanitizeInput(input: string): string {
  let cleaned = input;
  if (/^\s*javascript:/i.test(cleaned))
    cleaned = cleaned.replace(/^\s*javascript:/i, "[removed]");
  if (/^\s*data:/i.test(cleaned))
    cleaned = cleaned.replace(/^\s*data:/i, "[removed]");

  return cleaned
    .replace(/javascript:/gi, "[removed]")
    .replace(/data:/gi, "[removed]")
    .replace(/onload=|onerror=|onclick=/gi, "prevented=")
    .replace(/<[^>]*>/g, "")
    .trim();
}

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
 * Checks whether a string appears to contain HTML/XSS-risky content.
 * Never throws — uses DOMPurify if loaded, else the regex fallback.
 */
export function checkForHTMLTags(input: string): boolean {
  if (!input || typeof input !== "string" || !input.trim()) return false;

  kickOffLazyLoad();

  if (regexCheckForHTMLTags(input)) return true;

  if (sanitizerFn) {
    try {
      const clean = sanitizerFn(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
      return input.trim() !== clean.trim();
    } catch {
      console.warn(
        "[MajikUser] DOMPurify check failed at runtime, using regex fallback.",
      );
    }
  }

  return false;
}

/**
 * Sanitizes a string, stripping HTML/XSS-risky content.
 * Never throws — uses DOMPurify if loaded, else the regex fallback.
 */
export function sanitizeInput(input: string): string {
  if (!input || typeof input !== "string") return "";

  kickOffLazyLoad();

  let cleaned = input;
  if (/^\s*javascript:/i.test(cleaned))
    cleaned = cleaned.replace(/^\s*javascript:/i, "[removed]");
  if (/^\s*data:/i.test(cleaned))
    cleaned = cleaned.replace(/^\s*data:/i, "[removed]");

  if (sanitizerFn) {
    try {
      return sanitizerFn(cleaned, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true,
      }).trim();
    } catch {
      console.warn(
        "[MajikUser] DOMPurify sanitize failed at runtime, using regex fallback.",
      );
      return regexSanitizeInput(cleaned);
    }
  }

  return regexSanitizeInput(cleaned);
}
