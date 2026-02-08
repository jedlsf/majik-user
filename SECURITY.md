# Security Policy

Majik User is a security-hardened user domain model designed to reduce risk through
strict input policies, defensive validation, and safe serialization patterns.

This document explains the security philosophy, supported versions,
and how to report vulnerabilities responsibly.

---

## Supported Versions

Only the latest published version of Majik User is actively supported
with security updates.

| Version | Supported |
| ------- | --------- |
| Latest  | ✅ Yes     |
| Older   | ❌ No      |

Users are strongly encouraged to upgrade to the latest version.

---

## Security Philosophy

Majik User follows a **defense-in-depth** approach focused on
**reducing attack surface**, not claiming absolute security guarantees.

Core principles:

- Treat all user-controlled input as untrusted
- Enforce plain-text input for user-facing fields
- Reject or normalize unsafe markup early
- Separate private/internal data from public-facing output
- Favor predictable domain rules over complex sanitization logic

Majik User is **not** a replacement for:
- Frontend escaping
- Content Security Policy (CSP)
- Framework-level XSS protections
- Secure rendering practices

It is intended to act as **one layer** within a broader application security strategy.

---

## Threat Model Summary

Majik User is designed primarily to mitigate risks related to:

- Cross-Site Scripting (XSS) via user-controlled fields
- Unsafe URL injection (e.g. `javascript:` schemes)
- Accidental exposure of sensitive user data
- Inconsistent or unsafe user metadata structures

A full threat model is available in the project documentation.

---

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability, please report it
responsibly.

**Do not open public issues for security-related reports.**

### Preferred contact
- 📧 **Email**: business@thezelijah.world
- 📌 Subject: `Security Vulnerability Report – Majik User`

Please include:
- A clear description of the issue
- Steps to reproduce (if applicable)
- A minimal proof-of-concept
- Affected versions
- Potential impact assessment

You will receive an acknowledgment within **72 hours**.

---

## Disclosure Policy

- Valid vulnerabilities will be investigated promptly
- Fixes will be released as soon as reasonably possible
- Credit will be given to reporters unless anonymity is requested
- No legal action will be taken against good-faith research

Thank you for helping keep Majik User safe.
