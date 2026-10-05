import { beforeEach, describe, expect, it } from "vitest";
import { MajikUser } from "../src/core/majik-user";

import { checkForHTMLTags, sanitizeInput } from "../src/core/sanitize";

// ============================================================
// Red-team payload corpus
// ============================================================

const XSS_PAYLOADS = [
  `<script>alert(document.domain)</script>`,
  `<script src="https://evil.example/x.js"></script>`,
  `<img src=x onerror=alert(1)>`,
  `<img src=x onerror = alert(1)>`,
  `<svg/onload=alert(1)>`,
  `<svg onload="alert(1)"></svg>`,
  `<svg><script>alert(1)</script></svg>`,
  `<iframe src="javascript:alert(1)"></iframe>`,
  `<object data="javascript:alert(1)"></object>`,
  `<embed src="javascript:alert(1)">`,
  `<link rel="stylesheet" href="javascript:alert(1)">`,
  `<meta http-equiv="refresh" content="0;javascript:alert(1)">`,
  `<base href="javascript:alert(1)//">`,
  `<details open ontoggle=alert(1)>`,
  `<input autofocus onfocus=alert(1)>`,
  `<video><source onerror=alert(1)></video>`,
  `<audio src=x onerror=alert(1)>`,
  `<form action="javascript:alert(1)">`,
  `<a href="javascript:alert(1)">click</a>`,
  `<a href="java&#x73;cript:alert(1)">click</a>`,
  `<svg><a xlink:href="javascript:alert(1)">x</a></svg>`,
  `<div style="background:url(javascript:alert(1))">x</div>`,
  `<div style="width:expression(alert(1))">x</div>`,
  `<iframe srcdoc="<script>alert(1)</script>"></iframe>`,
  `</textarea><script>alert(1)</script>`,
  `</title><svg/onload=alert(1)>`,
  `"><img src=x onerror=alert(1)>`,
  `'><svg/onload=alert(1)>`,
  `javascript:alert(1)`,
  `JaVaScRiPt:alert(1)`,
  ` JAVASCRIPT:alert(1)`,
  `data:text/html,<svg/onload=alert(1)>`,
  `data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
  `vbscript:msgbox(1)`,
  `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`,
];

const ATTRIBUTE_INJECTION_PAYLOADS = [
  `onload=alert(1)`,
  `onerror=alert(1)`,
  `onclick=alert(1)`,
  `onmouseover=alert(1)`,
  `onfocus=alert(1)`,
  `onmouseenter=alert(1)`,
  `srcdoc="<script>alert(1)</script>"`,
  `href="javascript:alert(1)"`,
  `action="javascript:alert(1)"`,
  `style="background:url(javascript:alert(1))"`,
];

const DANGEROUS_URLS = [
  `javascript:alert(1)`,
  `JaVaScRiPt:alert(1)`,
  ` JAVASCRIPT:alert(1)`,
  `\tjavascript:alert(1)`,
  `\njavascript:alert(1)`,
  `data:text/html,<svg/onload=alert(1)>`,
  `data:image/svg+xml,<svg/onload=alert(1)>`,
  `vbscript:msgbox(1)`,
  `file:///etc/passwd`,
];

const SAFE_PICTURE_URLS = [
  `https://example.com/avatar.png`,
  `http://example.com/avatar.jpg`,
  `/local/avatar.png`,
  `#avatar`,
  `data:image/png;base64,iVBORw0KGgo=`,
  `data:image/jpeg;base64,/9j/`,
  `data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yw=`,
];

// ============================================================
// Helpers
// ============================================================

function createUser(): MajikUser {
  return MajikUser.initialize("security@example.com", "Security User");
}

/**
 * This intentionally checks for active/executable constructs rather
 * than requiring one exact sanitizer output.
 */
function expectNoExecutablePayload(value: unknown): void {
  const text = String(value ?? "");

  expect(text).not.toMatch(
    /<\s*(script|svg|img|iframe|object|embed|link|meta|base|style|form|video|audio|a)\b/i,
  );

  expect(text).not.toMatch(/\b(?:java|vb)script\s*:/i);
  expect(text).not.toMatch(/\bdata\s*:\s*(?:text\/html|image\/svg\+xml)/i);
  expect(text).not.toMatch(/\bon[a-z]+\s*=/i);
  expect(text).not.toMatch(/\bsrcdoc\s*=/i);
}

/**
 * Security APIs may either reject a payload or sanitize it.
 * Both are acceptable security outcomes.
 */
function expectRejectedOrSafe(
  action: () => void,
  readValue: () => unknown,
): void {
  let rejected = false;

  try {
    action();
  } catch {
    rejected = true;
  }

  if (rejected) {
    return;
  }

  expectNoExecutablePayload(readValue());
}

function getInternalMetadata(user: MajikUser): any {
  return (user as any)._metadata;
}

function getInternalSettings(user: MajikUser): any {
  return (user as any)._settings;
}

function makeValidSerializedUser(): any {
  const user = createUser();

  user.setName({
    first_name: "Jane",
    last_name: "Doe",
  });

  user.setBio("Normal profile");
  user.setPicture("https://example.com/avatar.png");

  return user.toJSON();
}

function expectNoGlobalPrototypePollution(marker: string): void {
  expect(({} as any)[marker]).toBeUndefined();
  expect((Object.prototype as any)[marker]).toBeUndefined();
}

// ============================================================
// Sanitizer / XSS boundary
// ============================================================

describe("MajikUser Security — XSS / Injection Hardening", () => {
  let user: MajikUser;

  beforeEach(() => {
    user = createUser();
  });

  describe("XSS detection corpus", () => {
    it("should detect all known XSS payloads", () => {
      for (const payload of XSS_PAYLOADS) {
        expect(
          checkForHTMLTags(payload),
          `Payload was not detected:\n${payload}`,
        ).toBe(true);
      }
    });

    it("should detect attribute-only injection payloads", () => {
      for (const payload of ATTRIBUTE_INJECTION_PAYLOADS) {
        expect(
          checkForHTMLTags(payload),
          `Attribute payload was not detected:\n${payload}`,
        ).toBe(true);
      }
    });

    it("should sanitize direct XSS payloads without returning executable markup", () => {
      for (const payload of XSS_PAYLOADS) {
        const cleaned = sanitizeInput(payload);

        expectNoExecutablePayload(cleaned);
        expect(
          checkForHTMLTags(cleaned),
          `Sanitized payload still looks dangerous:\n${cleaned}`,
        ).toBe(false);
      }
    });
  });

  describe("Standard user fields", () => {
    it("should reject XSS during initialization", () => {
      for (const payload of XSS_PAYLOADS) {
        expect(
          () => MajikUser.initialize("test@example.com", payload),
          `Initialization accepted XSS displayName:\n${payload}`,
        ).toThrow();
      }
    });

    it("should reject XSS through displayName setter", () => {
      for (const payload of XSS_PAYLOADS) {
        expect(() => {
          user.displayName = payload;
        }, `displayName accepted XSS:\n${payload}`).toThrow();
      }
    });

    it("should reject XSS in email values", () => {
      const maliciousEmails = [
        `user@example.com<script>alert(1)</script>`,
        `user@example.com<img src=x onerror=alert(1)>`,
        `user@example.com"><svg/onload=alert(1)>`,
      ];

      for (const email of maliciousEmails) {
        expect(
          () => MajikUser.initialize(email, "Normal User"),
          `initialize() accepted malicious email:\n${email}`,
        ).toThrow();

        expect(() => {
          user.email = email;
        }, `email setter accepted malicious email:\n${email}`).toThrow();
      }
    });

    it("should reject CRLF/header-injection style emails", () => {
      const payloads = [
        "user@example.com\r\nBcc: attacker@example.com",
        "user@example.com\nX-Injected: true",
        "user@example.com\rX-Injected: true",
      ];

      for (const email of payloads) {
        expect(() => {
          user.email = email;
        }).toThrow();
      }
    });

    it("should reject or neutralize XSS in bio", () => {
      for (const payload of XSS_PAYLOADS) {
        expectRejectedOrSafe(
          () => user.setBio(payload),
          () => user.metadata.bio,
        );
      }
    });

    it("should reject or neutralize XSS in first/last/middle/suffix names", () => {
      for (const payload of XSS_PAYLOADS) {
        expectRejectedOrSafe(
          () =>
            user.setName({
              first_name: payload,
              last_name: "Doe",
            }),
          () => user.metadata.name,
        );

        expectRejectedOrSafe(
          () =>
            user.setName({
              first_name: "John",
              last_name: payload,
            }),
          () => user.metadata.name,
        );

        expectRejectedOrSafe(
          () =>
            user.setName({
              first_name: "John",
              last_name: "Doe",
              middle_name: payload,
            }),
          () => user.metadata.name,
        );

        expectRejectedOrSafe(
          () =>
            user.setName({
              first_name: "John",
              last_name: "Doe",
              suffix: payload,
            }),
          () => user.metadata.name,
        );
      }
    });

    it("should reject or neutralize XSS in address fields", () => {
      const fields = [
        "building",
        "street",
        "area",
        "city",
        "region",
        "country",
      ] as const;

      for (const field of fields) {
        for (const payload of XSS_PAYLOADS) {
          expectRejectedOrSafe(
            () =>
              user.setAddress({
                [field]: payload,
              } as any),
            () => (user.metadata.address as any)?.[field],
          );
        }
      }
    });

    it("should reject or neutralize XSS in language and timezone", () => {
      for (const payload of XSS_PAYLOADS) {
        expectRejectedOrSafe(
          () => user.setLanguage(payload),
          () => user.metadata.language,
        );

        expectRejectedOrSafe(
          () => user.setTimezone(payload),
          () => user.metadata.timezone,
        );
      }
    });

    it("should reject or neutralize XSS in social link platform names and URLs", () => {
      for (const payload of XSS_PAYLOADS) {
        expectRejectedOrSafe(
          () => user.setSocialLink(payload, "https://example.com"),
          () => user.metadata.social_links,
        );

        expectRejectedOrSafe(
          () => user.setSocialLink("website", payload),
          () => user.metadata.social_links,
        );
      }
    });

    it("should reject or neutralize XSS injected into phone at runtime", () => {
      for (const payload of XSS_PAYLOADS) {
        expectRejectedOrSafe(
          () => user.setPhone(payload),
          () => user.metadata.phone,
        );
      }
    });

    it("should reject or neutralize runtime type-bypassed gender payloads", () => {
      for (const payload of XSS_PAYLOADS) {
        expectRejectedOrSafe(
          () => user.setGender(payload as any),
          () => user.metadata.gender,
        );
      }
    });
  });

  describe("URL / protocol attacks", () => {
    it("should block unsafe picture protocols", () => {
      for (const url of DANGEROUS_URLS) {
        expect(
          () => user.setPicture(url),
          `Unsafe picture URL was accepted:\n${url}`,
        ).toThrow();
      }
    });

    it("should reject executable SVG data URLs", () => {
      const svgPayloads = [
        `data:image/svg+xml,<svg/onload=alert(1)>`,
        `data:image/svg+xml,<svg><script>alert(1)</script></svg>`,
        `data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`,
      ];

      for (const url of svgPayloads) {
        expect(
          () => user.setPicture(url),
          `Executable SVG data URI was accepted:\n${url}`,
        ).toThrow();
      }
    });

    it("should continue allowing explicitly safe picture URL forms", () => {
      for (const url of SAFE_PICTURE_URLS) {
        expect(
          () => user.setPicture(url),
          `Expected safe picture URL to remain allowed:\n${url}`,
        ).not.toThrow();
      }
    });

    it("should not allow URL protocol obfuscation with leading control characters", () => {
      const payloads = [
        `\u0000javascript:alert(1)`,
        `\u0001javascript:alert(1)`,
        `\u0009javascript:alert(1)`,
        `\u000ajavascript:alert(1)`,
        `\u000djavascript:alert(1)`,
      ];

      for (const url of payloads) {
        expect(
          () => user.setPicture(url),
          `Protocol-smuggled URL was accepted:\n${JSON.stringify(url)}`,
        ).toThrow();
      }
    });
  });
});

// ============================================================
// Metadata bypasses / deep sanitization
// ============================================================

describe("MajikUser Security — Metadata Bypass Resistance", () => {
  let user: MajikUser;

  beforeEach(() => {
    user = createUser();
  });

  it("should not allow updateMetadata() to bypass XSS protections", () => {
    for (const payload of XSS_PAYLOADS) {
      expectRejectedOrSafe(
        () =>
          user.updateMetadata({
            bio: payload,
          } as any),
        () => user.metadata.bio,
      );
    }
  });

  it("should deep-sanitize nested metadata supplied through updateMetadata()", () => {
    const malicious = {
      profile: {
        about: `<img src=x onerror=alert(1)>`,
        website: `javascript:alert(1)`,
        nested: {
          html: `<svg/onload=alert(1)>`,
        },
      },
    };

    expectRejectedOrSafe(
      () => user.updateMetadata(malicious as any),
      () => JSON.stringify(getInternalMetadata(user)),
    );

    expectNoExecutablePayload(JSON.stringify(getInternalMetadata(user)));
  });

  it("should deep-sanitize nested arrays and objects through setMetadata()", () => {
    const maliciousValue = {
      items: [
        `<script>alert(1)</script>`,
        {
          html: `<img src=x onerror=alert(1)>`,
        },
        {
          deeper: {
            url: `javascript:alert(1)`,
          },
        },
      ],
    };

    expectRejectedOrSafe(
      () => user.setMetadata("custom" as any, maliciousValue as any),
      () => JSON.stringify(getInternalMetadata(user)),
    );

    expectNoExecutablePayload(JSON.stringify(getInternalMetadata(user)));
  });

  it("should not trust setMetadata() for picture URLs", () => {
    expectRejectedOrSafe(
      () =>
        user.setMetadata(
          "picture" as any,
          `javascript:alert(document.domain)` as any,
        ),
      () => user.metadata.picture,
    );
  });

  it("should not allow generic metadata updates to bypass social-link validation", () => {
    const maliciousSocialLinks = {
      github: `javascript:alert(1)`,
      website: `<img src=x onerror=alert(1)>`,
      linkedin: `https://example.com/profile`,
    };

    expectRejectedOrSafe(
      () =>
        user.setMetadata("social_links" as any, maliciousSocialLinks as any),
      () => JSON.stringify(user.metadata.social_links),
    );

    expectNoExecutablePayload(JSON.stringify(user.metadata.social_links));
  });

  it("should reject or neutralize arbitrary HTML entity encoded payloads", () => {
    const encodedPayloads = [
      `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`,
      `&lt;img src=x onerror=alert(1)&gt;`,
      `&#60;svg/onload=alert(1)&#62;`,
    ];

    for (const payload of encodedPayloads) {
      expectRejectedOrSafe(
        () => user.setMetadata("custom" as any, payload as any),
        // @ts-expect-error -
        () => user.metadata.custom,
      );
    }
  });
});

// ============================================================
// Prototype pollution
// ============================================================

describe("MajikUser Security — Prototype Pollution", () => {
  let user: MajikUser;

  beforeEach(() => {
    user = createUser();
  });

  it("should block __proto__ metadata pollution", () => {
    const marker = "__majikMetadataPolluted__";

    try {
      expectNoGlobalPrototypePollution(marker);

      expectRejectedOrSafe(
        () =>
          user.setMetadata(
            "__proto__" as any,
            {
              [marker]: true,
            } as any,
          ),
        () => getInternalMetadata(user)[marker],
      );

      expect(getInternalMetadata(user)[marker]).toBeUndefined();
      expectNoGlobalPrototypePollution(marker);
      expect(
        Object.getPrototypeOf(getInternalMetadata(user)),
      ).not.toHaveProperty(marker);
    } finally {
      delete (Object.prototype as any)[marker];
    }
  });

  it("should block __proto__ settings pollution", () => {
    const marker = "__majikSettingsPolluted__";

    try {
      expectNoGlobalPrototypePollution(marker);

      expectRejectedOrSafe(
        () =>
          user.setSetting("__proto__", {
            [marker]: true,
          }),
        () => getInternalSettings(user)[marker],
      );

      expect(getInternalSettings(user)[marker]).toBeUndefined();
      expectNoGlobalPrototypePollution(marker);
    } finally {
      delete (Object.prototype as any)[marker];
    }
  });

  it("should block constructor/prototype pollution payloads", () => {
    const marker = "__majikConstructorPolluted__";

    try {
      const payload = {
        constructor: {
          prototype: {
            [marker]: true,
          },
        },
      };

      expectRejectedOrSafe(
        () => user.updateMetadata(payload as any),
        () => JSON.stringify(getInternalMetadata(user)),
      );

      expectNoGlobalPrototypePollution(marker);
    } finally {
      delete (Object.prototype as any)[marker];
    }
  });

  it("should not allow a malicious social-links __proto__ key to alter the resulting object's prototype", () => {
    const marker = "__majikSocialPolluted__";

    try {
      const data = makeValidSerializedUser();

      data.metadata.social_links = JSON.parse(
        JSON.stringify({
          __proto__: {
            [marker]: true,
          },
          github: "https://github.com/example",
        }),
      );

      const restored = MajikUser.fromJSON(data);

      const socialLinks = restored.metadata.social_links as any;

      expect(socialLinks?.[marker]).toBeUndefined();
      expect(Object.getPrototypeOf(socialLinks)?.[marker]).toBeUndefined();
      expectNoGlobalPrototypePollution(marker);
    } finally {
      delete (Object.prototype as any)[marker];
    }
  });

  it("should not allow malicious app_metadata keys from Supabase to pollute settings", () => {
    const marker = "__majikSupabasePolluted__";

    try {
      const supabasePayload: any = {
        id: "supabase-security-user",
        email: "security@example.com",
        aud: "authenticated",
        created_at: new Date().toISOString(),
        app_metadata: JSON.parse(
          JSON.stringify({
            __proto__: {
              [marker]: true,
            },
            notifications: true,
            is_restricted: false,
          }),
        ),
        user_metadata: {
          display_name: "Security User",
        },
      };

      const restored = MajikUser.fromSupabase(supabasePayload);

      expect((getInternalSettings(restored) as any)[marker]).toBeUndefined();
      expectNoGlobalPrototypePollution(marker);
    } finally {
      delete (Object.prototype as any)[marker];
    }
  });

  it("should reject prototype-sensitive metadata keys rather than treating them as normal application data", () => {
    const dangerousKeys = ["__proto__", "prototype", "constructor"];

    for (const key of dangerousKeys) {
      expectRejectedOrSafe(
        () =>
          user.setMetadata(
            key as any,
            {
              polluted: true,
            } as any,
          ),
        () => JSON.stringify(getInternalMetadata(user)),
      );

      expectNoGlobalPrototypePollution("polluted");
    }
  });
});

// ============================================================
// Deserialization / payload manipulation
// ============================================================

describe("MajikUser Security — Deserialization Hardening", () => {
  it("should reject malformed JSON strings", () => {
    const payloads = [
      "",
      " ",
      "{",
      `{"id":}`,
      `not-json`,
      `null`,
      `undefined`,
      `[]`,
    ];

    for (const payload of payloads) {
      expect(
        () => MajikUser.fromJSON(payload as any),
        `Malformed JSON was accepted:\n${payload}`,
      ).toThrow();
    }
  });

  it("should reject non-object JSON values", () => {
    const payloads = [null, true, false, 0, 1, "string", []];

    for (const payload of payloads) {
      expect(() => MajikUser.fromJSON(payload as any)).toThrow();
    }
  });

  it("should reject JSON missing required fields", () => {
    const cases = [
      { id: "id", displayName: "User", hash: "hash" },
      { id: "id", email: "user@example.com", hash: "hash" },
      { email: "user@example.com", displayName: "User", hash: "hash" },
      { id: "id", email: "user@example.com", displayName: "User" },
    ];

    for (const payload of cases) {
      expect(() => MajikUser.fromJSON(payload as any)).toThrow();
    }
  });

  it("should reject invalid email during deserialization", () => {
    const data = makeValidSerializedUser();

    data.email = `not-an-email<script>alert(1)</script>`;

    expect(() => MajikUser.fromJSON(data)).toThrow();
  });

  it("should reject XSS-bearing IDs during deserialization", () => {
    const payloads = [
      `<script>alert(1)</script>`,
      `<img src=x onerror=alert(1)>`,
      `"><svg/onload=alert(1)>`,
      `\u0000<script>alert(1)</script>`,
    ];

    for (const id of payloads) {
      const data = makeValidSerializedUser();
      data.id = id;

      expect(
        () => MajikUser.fromJSON(data),
        `Malicious ID was accepted:\n${id}`,
      ).toThrow();
    }
  });

  it("should reject invalid createdAt dates", () => {
    const data = makeValidSerializedUser();

    data.createdAt = "not-a-date";

    expect(() => MajikUser.fromJSON(data)).toThrow();
  });

  it("should reject invalid lastUpdate dates", () => {
    const data = makeValidSerializedUser();

    data.lastUpdate = "not-a-date";

    expect(() => MajikUser.fromJSON(data)).toThrow();
  });

  it("should detect serialized hash tampering", () => {
    const data = makeValidSerializedUser();

    data.hash = "attacker-controlled-hash";

    expect(() => MajikUser.fromJSON(data)).toThrow();
  });

  it("should not trust serialized displayName XSS", () => {
    for (const payload of XSS_PAYLOADS) {
      const data = makeValidSerializedUser();

      data.displayName = payload;

      let restored: MajikUser | undefined;
      let rejected = false;

      try {
        restored = MajikUser.fromJSON(data);
      } catch {
        rejected = true;
      }

      if (rejected) {
        continue;
      }

      expect(restored).toBeDefined();

      expectNoExecutablePayload(restored!.displayName);

      expect(checkForHTMLTags(restored!.displayName)).toBe(false);
    }
  });

  it("should not trust serialized nested metadata XSS", () => {
    const data = makeValidSerializedUser();

    data.metadata = {
      ...data.metadata,
      bio: XSS_PAYLOADS[0],
      name: {
        first_name: XSS_PAYLOADS[1],
        last_name: "Doe",
      },
      address: {
        city: XSS_PAYLOADS[2],
      },
      social_links: {
        website: XSS_PAYLOADS[3],
      },
      picture: `javascript:alert(1)`,
    };

    expectRejectedOrSafe(
      () => {
        const restored = MajikUser.fromJSON(data);

        expectNoExecutablePayload(restored.metadata.bio);
        expectNoExecutablePayload(restored.metadata.name?.first_name);
        expectNoExecutablePayload(restored.metadata.address?.city);
        expectNoExecutablePayload(
          restored.metadata.social_links &&
            JSON.stringify(restored.metadata.social_links),
        );
        expectNoExecutablePayload(restored.metadata.picture);
      },
      () => data.metadata,
    );
  });

  it("should reject non-object metadata containers", () => {
    const invalidMetadataValues = [[], "metadata", 123, true, false];

    for (const metadata of invalidMetadataValues) {
      const data = makeValidSerializedUser();

      data.metadata = metadata;

      expect(() => MajikUser.fromJSON(data)).toThrow();
    }
  });

  it("should reject non-object settings containers", () => {
    const invalidSettingsValues = [[], "settings", 123, true, false];

    for (const settings of invalidSettingsValues) {
      const data = makeValidSerializedUser();

      data.settings = settings;

      expect(() => MajikUser.fromJSON(data)).toThrow();
    }
  });

  it("should reject metadata with attacker-controlled prototypes", () => {
    const marker = "__majikInherited__";

    const data = makeValidSerializedUser();

    const metadata = Object.create({
      [marker]: "attacker-data",
    });

    Object.assign(metadata, data.metadata);

    data.metadata = metadata;

    expect(() => MajikUser.fromJSON(data)).toThrow();
  });
});

// ============================================================
// Verification / privilege escalation
// ============================================================

describe("MajikUser Security — Verification State Integrity", () => {
  it("should not allow generic metadata APIs to forge complete verification", () => {
    const user = createUser();

    expect(user.isFullyVerified).toBe(false);

    expectRejectedOrSafe(
      () =>
        user.setMetadata(
          "verification" as any,
          {
            email_verified: true,
            phone_verified: true,
            identity_verified: true,
          } as any,
        ),
      () => user.isFullyVerified,
    );

    expect(user.isFullyVerified).toBe(false);
  });

  it("should not allow updateMetadata() to forge complete verification", () => {
    const user = createUser();

    expectRejectedOrSafe(
      () =>
        user.updateMetadata({
          verification: {
            email_verified: true,
            phone_verified: true,
            identity_verified: true,
          },
        } as any),
      () => user.isFullyVerified,
    );

    expect(user.isFullyVerified).toBe(false);
  });

  it("should still allow legitimate verification methods", () => {
    const user = createUser();

    user.verifyEmail();
    user.verifyPhone();
    user.verifyIdentity();

    expect(user.isFullyVerified).toBe(true);
  });

  it("should revoke email verification when email changes", () => {
    const user = createUser();

    user.verifyEmail();
    expect(user.isEmailVerified).toBe(true);

    user.email = "new@example.com";

    expect(user.isEmailVerified).toBe(false);
  });

  it("should revoke phone verification when phone changes", () => {
    const user = createUser();

    user.verifyPhone();
    expect(user.isPhoneVerified).toBe(true);

    user.setPhone("+639171234567");

    expect(user.isPhoneVerified).toBe(false);
  });
});

// ============================================================
// Runtime immutability / reference attacks
// ============================================================

describe("MajikUser Security — Object Reference / Mutation Attacks", () => {
  it("should not let metadata getter mutation alter internal state", () => {
    const user = createUser();

    user.setName({
      first_name: "Jane",
      last_name: "Doe",
    });

    const exposed = user.metadata as any;

    exposed.name.first_name = `<img src=x onerror=alert(1)>`;

    expect(user.firstName).toBe("Jane");
    expectNoExecutablePayload(user.firstName);
  });

  it("should not let settings getter mutation alter internal state", () => {
    const user = createUser();

    const exposed = user.settings as any;

    exposed.system.isRestricted = true;
    exposed.system.restrictedUntil = new Date(Date.now() + 60_000);

    expect(user.isCurrentlyRestricted()).toBe(false);
    expect(getInternalSettings(user).system.isRestricted).toBe(false);
  });

  it("should not expose a mutable fullNameObject reference", () => {
    const user = createUser();

    user.setName({
      first_name: "Jane",
      last_name: "Doe",
    });

    const exposed = user.fullNameObject as any;

    exposed.first_name = `<script>alert(1)</script>`;

    expect(user.firstName).toBe("Jane");
    expectNoExecutablePayload(user.firstName);
  });

  it("should not expose a mutable createdAt Date object", () => {
    const user = createUser();

    const originalTime = user.createdAt.getTime();

    user.createdAt.setTime(0);

    expect(user.createdAt.getTime()).toBe(originalTime);
  });

  it("should not allow runtime mutation of readonly id", () => {
    const user = createUser();

    const originalId = user.id;

    try {
      (user as any).id = `attacker-id`;
    } catch {
      // Runtime-hardening may throw, which is acceptable.
    }

    expect(user.id).toBe(originalId);
  });

  it("should not allow changing the identity hash to an arbitrary value", () => {
    const user = createUser();

    const originalHash = user.hash;

    expect(() => {
      user.hash = `attacker-controlled-hash`;
    }).toThrow();

    expect(user.hash).toBe(originalHash);
  });

  it("should return a deep-safe JSON snapshot", () => {
    const user = createUser();

    user.setName({
      first_name: "Jane",
      last_name: "Doe",
    });

    const json = user.toJSON();

    (json.metadata as any).name.first_name = `<svg/onload=alert(1)>`;

    expect(user.firstName).toBe("Jane");
    expectNoExecutablePayload(user.firstName);
  });

  it("should return a deep-independent clone", () => {
    const user = createUser();

    user.setName({
      first_name: "Jane",
      last_name: "Doe",
    });

    user.updateSettings({
      system: {
        isRestricted: false,
      },
    });

    const clone = user.clone();

    (clone.metadata as any).name.first_name = `<script>alert(1)</script>`;

    (clone.settings as any).system.isRestricted = true;

    expect(user.firstName).toBe("Jane");
    expect(user.isCurrentlyRestricted()).toBe(false);
  });
});

// ============================================================
// Serialization sinks
// ============================================================

describe("MajikUser Security — Serialization / Output Safety", () => {
  it("should never emit active XSS payloads through toPublicJSON()", () => {
    const user = createUser();

    // Intentionally bypass the setter to simulate a compromised
    // deserializer / external payload / legacy state.
    (user as any)._metadata.bio = XSS_PAYLOADS[0];
    (user as any)._metadata.picture = DANGEROUS_URLS[0];

    const publicData = user.toPublicJSON();

    expectNoExecutablePayload(publicData.bio);
    expectNoExecutablePayload(publicData.picture);
  });

  it("should never emit active XSS payloads through toSupabaseJSON()", () => {
    const user = createUser();

    (user as any)._metadata.bio = XSS_PAYLOADS[1];
    (user as any)._metadata.picture = DANGEROUS_URLS[0];

    expect(() => user.toSupabaseJSON()).toThrow();
  });

  it("should never serialize dangerous nested metadata without validation", () => {
    const user = createUser();

    (user as any)._metadata = {
      ...getInternalMetadata(user),
      custom: {
        html: `<img src=x onerror=alert(1)>`,
        url: `javascript:alert(1)`,
      },
    };

    const json = user.toJSON();

    expectNoExecutablePayload(JSON.stringify(json.metadata));
  });

  it("should not leak private fields through public serialization", () => {
    const user = createUser();

    const publicData = user.toPublicJSON() as any;

    expect(publicData.email).toBeUndefined();
    expect(publicData.hash).toBeUndefined();
    expect(publicData.settings).toBeUndefined();
    expect(publicData.metadata).toBeUndefined();
  });
});

// ============================================================
// Supabase trust boundary
// ============================================================

describe("MajikUser Security — Supabase Input Hardening", () => {
  it("should reject malicious Supabase identity fields", () => {
    const payloads = [
      `<script>alert(1)</script>`,
      `<img src=x onerror=alert(1)>`,
      `"><svg/onload=alert(1)>`,
    ];

    for (const payload of payloads) {
      const supabaseUser: any = {
        id: "supabase-user",
        email: "user@example.com",
        aud: "authenticated",
        created_at: new Date().toISOString(),
        app_metadata: {},
        user_metadata: {
          display_name: payload,
        },
      };

      expect(() => MajikUser.fromSupabase(supabaseUser)).toThrow();
    }
  });

  it("should not trust malicious Supabase picture URLs", () => {
    const supabaseUser: any = {
      id: "supabase-user",
      email: "user@example.com",
      aud: "authenticated",
      created_at: new Date().toISOString(),
      app_metadata: {},
      user_metadata: {
        display_name: "Normal User",
        picture: `javascript:alert(1)`,
      },
    };

    expectRejectedOrSafe(
      () => {
        const user = MajikUser.fromSupabase(supabaseUser);
        expectNoExecutablePayload(user.metadata.picture);
      },
      () => supabaseUser.user_metadata.picture,
    );
  });

  it("should not trust malicious Supabase phone/gender/pronoun values", () => {
    const maliciousValues = [
      `<img src=x onerror=alert(1)>`,
      `javascript:alert(1)`,
      `<svg/onload=alert(1)>`,
    ];

    for (const value of maliciousValues) {
      const supabaseUser: any = {
        id: "supabase-user",
        email: "user@example.com",
        aud: "authenticated",
        created_at: new Date().toISOString(),
        app_metadata: {},
        user_metadata: {
          display_name: "Normal User",
          phone: value,
          gender: value,
          pronouns: value,
        },
      };

      expectRejectedOrSafe(
        () => {
          const restored = MajikUser.fromSupabase(supabaseUser);

          expectNoExecutablePayload(restored.metadata.phone);
          expectNoExecutablePayload(restored.metadata.gender);
          expectNoExecutablePayload(restored.metadata.pronouns);
        },
        () => JSON.stringify(supabaseUser.user_metadata),
      );
    }
  });

  it("should reject malicious Supabase social links", () => {
    const supabaseUser: any = {
      id: "supabase-user",
      email: "user@example.com",
      aud: "authenticated",
      created_at: new Date().toISOString(),
      app_metadata: {},
      user_metadata: {
        display_name: "Normal User",
        social_links: {
          website: `javascript:alert(1)`,
          github: `<img src=x onerror=alert(1)>`,
        },
      },
    };

    expect(() => MajikUser.fromSupabase(supabaseUser)).toThrow();
  });
});

// ============================================================
// Resource / parser abuse
// ============================================================

describe("MajikUser Security — Payload Size / Robustness", () => {
  it("should handle a large malicious string without throwing a parser-level exception", () => {
    const user = createUser();

    const hugePayload = `<img src=x onerror=alert(1)>` + "A".repeat(250_000);

    expectRejectedOrSafe(
      () => user.setBio(hugePayload),
      () => user.metadata.bio,
    );
  });

  it("should handle repeated nested malicious structures without leaking executable content", () => {
    const user = createUser();

    const payload = {
      level1: {
        level2: {
          level3: {
            html: `<svg/onload=alert(1)>`,
            url: `javascript:alert(1)`,
          },
        },
      },
    };

    expectRejectedOrSafe(
      () => user.updateMetadata(payload as any),
      () => JSON.stringify(getInternalMetadata(user)),
    );

    expectNoExecutablePayload(JSON.stringify(getInternalMetadata(user)));
  });

  it("should not crash on unusual but valid Unicode input", () => {
    const user = createUser();

    const unicodeValues = [
      "José Fabian",
      "测试用户",
      "ユーザー",
      "مستخدم",
      "사용자",
      "🧙‍♂️ Majikah",
      "Zelijah — Developer",
    ];

    for (const value of unicodeValues) {
      expect(() => {
        user.displayName = value;
      }).not.toThrow();

      expectNoExecutablePayload(user.displayName);
    }
  });
});
