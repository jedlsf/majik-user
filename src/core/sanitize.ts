type SanitizeFn = (input: string, config?: Record<string, unknown>) => string;

let sanitizerFn: SanitizeFn | null = null;
let sanitizerChecked = false;
let sanitizerLoadingPromise: Promise<void> | null = null;

const OPTIONAL_SANITIZER_PKG = "isomorphic-dompurify";

/**
 * These regexes intentionally do NOT use /g.
 * RegExp.prototype.test() is stateful for global regexes.
 */
const DANGER_PATTERNS: RegExp[] = [
  // Any HTML tag.
  /<\s*\/?\s*[a-z][^>]*>/i,

  // Common dangerous elements even when malformed/incomplete.
  /<\s*\/?\s*(script|svg|img|iframe|object|embed|link|meta|style|base|form|video|audio)\b/i,

  // HTML event-handler attributes.
  /\bon[a-z0-9:_-]+\s*=/i,

  // iframe HTML injection.
  /\bsrcdoc\s*=/i,

  // Dangerous protocols.
  /(?:^|[^\w.-])(?:javascript|vbscript|data)\s*:/i,

  // Entity encoded markup/protocols.
  /&(?:#x?[0-9a-f]+|[a-z][a-z0-9]+);/i,

  // Legacy CSS execution.
  /\bexpression\s*\(/i,
];

const JAVASCRIPT_PROTOCOL_RE =
  /j[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*a[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*v[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*a[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*s[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*c[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*r[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*i[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*p[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*t\s*:/gi;

const VBSCRIPT_PROTOCOL_RE =
  /v[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*b[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*s[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*c[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*r[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*i[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*p[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*t\s*:/gi;

const DATA_PROTOCOL_RE =
  /d[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*a[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*t[\s\u0000-\u0020\u007f-\u009f\u200b-\u200d\ufeff]*a\s*:/gi;

const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f-\u009f]/g;

function normalizeSecurityText(input: string): string {
  return input.normalize("NFKC").replace(CONTROL_CHARS_RE, "");
}

function regexCheckForHTMLTags(input: string): boolean {
  const normalized = normalizeSecurityText(input);

  if (DANGER_PATTERNS.some((pattern) => pattern.test(normalized))) {
    return true;
  }

  /*
   * Explicitly detect event handlers with no surrounding HTML:
   *
   * onload=...
   * onfocus=...
   * onmouseover=...
   */
  if (/\bon[a-z0-9:_-]+\s*=/i.test(normalized)) {
    return true;
  }

  /*
   * Detect whitespace/control-character obfuscation.
   */
  const compact = normalized.replace(/\s+/g, "");

  if (/(?:^|[^\w.-])(?:javascript|vbscript|data):/i.test(compact)) {
    return true;
  }

  return false;
}

function regexSanitizeInput(input: string): string {
  let cleaned = normalizeSecurityText(input);

  // Dangerous protocols, including obfuscated forms.
  cleaned = cleaned.replace(JAVASCRIPT_PROTOCOL_RE, "[removed]");

  cleaned = cleaned.replace(VBSCRIPT_PROTOCOL_RE, "[removed]");

  cleaned = cleaned.replace(DATA_PROTOCOL_RE, "[removed]");

  // Any HTML event-handler attribute.
  cleaned = cleaned.replace(
    /\bon[a-z0-9:_-]+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s<]+)/gi,
    "[removed]",
  );

  // iframe document injection.
  cleaned = cleaned.replace(
    /\bsrcdoc\s*=\s*(?:"[^"]*"|'[^']*'|[^\s<]+)/gi,
    "[removed]",
  );

  // Legacy CSS execution.
  cleaned = cleaned.replace(/\bexpression\s*\(/gi, "[removed](");

  // HTML comments.
  cleaned = cleaned.replace(/<!--[\s\S]*?(?:-->|$)/g, "");

  /*
   * Remove tag-like constructs even when the attacker has
   * deliberately made the tag malformed by stripping its
   * closing ">" during an earlier sanitization pass.
   *
   * Examples:
   *   <img src=x
   *   <svg/[removed]
   *   <script
   */
  cleaned = cleaned.replace(/<\s*\/?\s*[a-z][^>]*(?:>|$)/gi, "");

  // Remove any remaining complete HTML tags.
  cleaned = cleaned.replace(/<[^>]*>/g, "");

  // HTML entities.
  cleaned = cleaned.replace(/&(?:#x?[0-9a-f]+|[a-z][a-z0-9]+);/gi, "");

  return cleaned.trim();
}

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
      throw new Error("sanitize() unavailable");
    }

    sanitizerFn = fn.bind(dp);
  } catch {
    sanitizerFn = null;

    console.warn(
      "[MajikUser] DOMPurify unavailable; using hardened built-in sanitizer fallback.",
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

function kickOffLazyLoad(): void {
  if (!sanitizerChecked && !sanitizerLoadingPromise) {
    void ensureSanitizerLoading();
  }
}

export async function preloadMajikSanitizer(): Promise<boolean> {
  await ensureSanitizerLoading();
  return sanitizerFn !== null;
}

export function checkForHTMLTags(input: string): boolean {
  if (typeof input !== "string" || !input.trim()) {
    return false;
  }

  kickOffLazyLoad();

  /*
   * Always run deterministic synchronous checks first.
   */
  if (regexCheckForHTMLTags(input)) {
    return true;
  }

  if (sanitizerFn) {
    try {
      const clean = sanitizerFn(input, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
      });

      return input.trim() !== clean.trim();
    } catch {
      console.warn(
        "[MajikUser] DOMPurify check failed; using built-in fallback.",
      );
    }
  }

  return false;
}

export function sanitizeInput(input: string): string {
  if (typeof input !== "string" || input.length === 0) {
    return "";
  }

  kickOffLazyLoad();

  /*
   * Always sanitize using our deterministic
   * fallback first.
   */
  let cleaned = regexSanitizeInput(input);

  /*
   * DOMPurify becomes an additional layer,
   * never the only layer.
   */
  if (sanitizerFn) {
    try {
      cleaned = sanitizerFn(cleaned, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true,
      });
    } catch {
      console.warn(
        "[MajikUser] DOMPurify sanitize failed; using built-in fallback.",
      );
    }
  }

  return regexSanitizeInput(cleaned);
}

const FORBIDDEN_OBJECT_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
]);

export function assertSafeObjectKey(key: string): void {
  if (FORBIDDEN_OBJECT_KEYS.has(key)) {
    throw new Error(`Unsafe object key detected: ${key}`);
  }
}

export function isPlainObject(
  value: unknown,
): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    return false;
  }

  if (Array.isArray(value)) {
    return false;
  }

  const proto = Object.getPrototypeOf(value);

  return proto === Object.prototype || proto === null;
}

export function deepSanitize<T>(value: T): T {
  const seen = new WeakSet<object>();

  const walk = (input: unknown, path: string): unknown => {
    if (typeof input === "string") {
      return sanitizeInput(input);
    }

    if (
      input === null ||
      typeof input === "boolean" ||
      typeof input === "undefined"
    ) {
      return input;
    }

    if (typeof input === "number") {
      if (!Number.isFinite(input)) {
        throw new Error(`Invalid numeric value at ${path}`);
      }

      return input;
    }

    if (
      typeof input === "bigint" ||
      typeof input === "symbol" ||
      typeof input === "function"
    ) {
      throw new Error(`Unsupported value at ${path}`);
    }

    if (input instanceof Date) {
      if (Number.isNaN(input.getTime())) {
        throw new Error(`Invalid Date at ${path}`);
      }

      return new Date(input.getTime());
    }

    if (typeof input !== "object" || input === null) {
      throw new Error(`Unsupported value at ${path}`);
    }

    if (seen.has(input)) {
      throw new Error(`Circular reference detected at ${path}`);
    }

    seen.add(input);

    try {
      if (Array.isArray(input)) {
        const output: unknown[] = [];

        for (let i = 0; i < input.length; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(input, String(i));

          if (!descriptor || !("value" in descriptor)) {
            throw new Error(`Accessor property rejected at ${path}[${i}]`);
          }

          output[i] = walk(descriptor.value, `${path}[${i}]`);
        }

        return output;
      }

      if (!isPlainObject(input)) {
        throw new Error(`Non-plain object rejected at ${path}`);
      }

      for (const symbol of Object.getOwnPropertySymbols(input)) {
        throw new Error(
          `Symbol property rejected at ${path}: ${String(symbol)}`,
        );
      }

      const output: Record<string, unknown> = {};

      for (const key of Object.keys(input)) {
        assertSafeObjectKey(key);

        const descriptor = Object.getOwnPropertyDescriptor(input, key);

        if (!descriptor || !("value" in descriptor)) {
          throw new Error(`Accessor property rejected at ${path}.${key}`);
        }

        output[key] = walk(descriptor.value, `${path}.${key}`);
      }

      return output;
    } finally {
      seen.delete(input);
    }
  };

  return walk(value, "value") as T;
}
