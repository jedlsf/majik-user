# Majik User

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik User** is a framework-agnostic, **self-defending** user domain model for modern applications. It provides a strongly typed foundation for managing identity, profile data, and settings, with built-in XSS protection and input sanitization baked directly into the class logic.

This package is designed to be the **isomorphic source of truth**—ensuring that user data remains clean, validated, and secure as it moves between your frontend, backend, and database.

![npm](https://img.shields.io/npm/v/@thezelijah/majik-user) ![npm downloads](https://img.shields.io/npm/dm/@thezelijah/majik-user) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40thezelijah%2Fmajik-user) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)



---

- [Majik User](#majik-user)
  - [Why Majik User?](#why-majik-user)
  - [Features](#features)
    - [Security \& Integrity](#security--integrity)
    - [Core User Management](#core-user-management)
    - [Rich Profile Metadata](#rich-profile-metadata)
    - [Verification System](#verification-system)
    - [Settings \& Restrictions](#settings--restrictions)
    - [Serialization \& Interop](#serialization--interop)
    - [Developer Ergonomics](#developer-ergonomics)
  - [Installation](#installation)
    - [Using Cloudflare Workers?](#using-cloudflare-workers)
  - [Usage](#usage)
    - [Initializing a New User](#initializing-a-new-user)
    - [Updating User Data](#updating-user-data)
      - [Security in Action](#security-in-action)
      - [Basic Info](#basic-info)
      - [Profile Metadata](#profile-metadata)
      - [Birthdate](#birthdate)
      - [Address](#address)
      - [Social Links](#social-links)
    - [Verification Methods](#verification-methods)
    - [Restricting a user](#restricting-a-user)
    - [Reading Computed Properties](#reading-computed-properties)
    - [Validation](#validation)
    - [Serialization \& Parsing](#serialization--parsing)
      - [Serialize for storage](#serialize-for-storage)
      - [Parse from JSON](#parse-from-json)
      - [Public-safe JSON (no sensitive data)](#public-safe-json-no-sensitive-data)
  - [Extending Majik User](#extending-majik-user)
  - [Data Integrity \& Security](#data-integrity--security)
  - [Supabase Integration (Optional)](#supabase-integration-optional)
    - [Public Signup (POST `/api/users`)](#public-signup-post-apiusers)
      - [Why this works well](#why-this-works-well)
    - [Fetching a User by ID (GET `/api/users/:id`)](#fetching-a-user-by-id-get-apiusersid)
      - [Notes](#notes)
    - [Updating a User (PUT `/api/users/:id`)](#updating-a-user-put-apiusersid)
      - [Why this pattern is recommended](#why-this-pattern-is-recommended)
  - [Philosophy](#philosophy)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)


---

## Why Majik User?

**Secure by Default: Built-in XSS protection and protocol-safe URI validation—no "dirty" data enters your system.**

Most apps scatter user logic across:
- database schemas
- auth provider objects
- API DTOs
- frontend state

**Majik User centralizes all of that logic into one predictable, reusable domain object.**

It is:
- Strongly typed (TypeScript-first)
- Serializable and persistence-ready
- Extensible via generics
- Safe by default (public vs private data)
- Compatible with [Supabase](https://www.npmjs.com/package/supabase) (optional)

---

## Features

### Security & Integrity
- **XSS Defense:** Automatic sanitization of all string inputs using DOMPurify.
- **Self-Defending Setters:** Setters validate and clean data in real-time before it reaches the internal state.
- **Safe URI Enforcement:** Profile pictures and social links are restricted to safe protocols (`https, base64, etc.`), blocking javascript: injection.
- **Readonly State:** Getters return deep copies or readonly versions of data to prevent accidental state mutation.

### Core User Management
- Unique user ID generation (UUID)
- Email + display name validation
- Automatic timestamps (`createdAt`, `lastUpdate`)
- SHA-256–based hashed identifier

### Rich Profile Metadata
- Full name handling (first, middle, last, suffix)
- Profile picture, bio, phone, gender
- Birthdate with age calculation
- Address formatting
- Social links
- Language and timezone preferences

### Verification System
- Email verification
- Phone verification
- Identity (KYC-style) verification
- Combined `isFullyVerified` status

### Settings & Restrictions
- Notification preferences
- System-level restrictions
- Temporary or permanent account restriction
- Restriction expiration checks

### Serialization & Interop
- `toJSON()` for database persistence
- `fromJSON()` for hydration
- `toPublicJSON()` for safe public exposure
- `toSupabaseJSON()` and `fromSupabase()` helpers

### Developer Ergonomics
- Generic metadata support
- Profile completeness scoring
- Built-in validation with error reporting
- Cloneable user instances
- Designed to be subclassed

---


## Installation

```bash
npm install @thezelijah/majik-user
```

### Using Cloudflare Workers? 

Majik User uses isomorphic-dompurify for high-grade security. To run this in a Cloudflare Worker environment, you must **enable Node.js compatibility** in your wrangler configuration.

Add the following to your wrangler.json (or .toml):

```json
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "compatibility_date": "2025-09-27",
  "compatibility_flags": ["nodejs_compat"]
}
```

---

## Usage

```ts
import { MajikUser } from "@thezelijah/majik-user";
```

### Initializing a New User

```ts


const user = MajikUser.initialize(
  "business@thezelijah.world",
  "Zelijah"
);

```

What this does:

- Generates a UUID if no ID is provided
- Hashes the user ID
- Sets default metadata and settings
- Sets createdAt and lastUpdate
- Validates email and display name

You can optionally provide your own ID:
```ts

const generatedID: string = customIDGenerator();

const user = MajikUser.initialize(
  "business@thezelijah.world",
  "Zelijah",
  generatedID
);

```

### Updating User Data


#### Security in Action

```ts


// 1. Protection against XSS
try {
  user.displayName = "<script>alert('hacked')</script> Josef";
} catch (e) {
  // Throws: "Display name contains suspicious HTML tags"
}

// 2. Protocol Safety
try {
  user.setPicture("javascript:alert('xss')");
} catch (e) {
  // Throws: "Invalid or unsafe URL protocol detected."
}

// 3. Auto-Sanitization on Metadata
user.setMetadata("bio", "I love <b>coding</b> <img src=x onerror=alert(1)>");
console.log(user.metadata.bio); 
// Output: "I love <b>coding</b>" (Harmful tags stripped automatically)

```

#### Basic Info

```ts


user.email = "business@majikah.solutions";
user.displayName = "Josef";

```

> Changing email or phone automatically marks them as unverified.

#### Profile Metadata

```ts


user.setName({
  first_name: "Josef",
  last_name: "Fabian",
});

user.setBio("Creative technologist and builder.");
user.setPicture("https://thezelijah.world/avatar.png");
user.setPhone("+639123456789");
user.setGender("male");
user.setLanguage("en");
user.setTimezone("Asia/Manila");


```

#### Birthdate

```ts


user.setBirthdate("1995-10-26");
// or
user.setBirthdate(new Date("1995-10-26"));

```
You can then access:

```ts


user.age;       // number | null
user.birthday; // YYYY-MM-DD | null

```

#### Address

```ts

user.setAddress({
  street: "123 Main St",
  city: "Manila",
  country: "PH",
});

```
You can then access:

```ts


user.address; // "123 ABC St, Manila, PH"

```

#### Social Links

```ts

user.setSocialLink("Instagram", "https://instagram.com/thezelijah");
user.removeSocialLink("Instagram");

```

---

### Verification Methods

```ts


user.verifyEmail();
user.verifyPhone();
user.verifyIdentity();

user.isEmailVerified;
user.isFullyVerified;

```
You can also unverify:

```ts


user.unverifyEmail();
user.unverifyPhone();
user.unverifyIdentity();

```

---

### Restricting a user

```ts


// Restrict indefinitely
user.restrict();

// Restrict until a specific date
user.restrict(new Date("2026-01-01"));

```
```ts


user.isCurrentlyRestricted(); // boolean

```
To remove restriction:

```ts


user.unrestrict();

```

---
### Reading Computed Properties

```ts


user.fullName;
user.formattedName;
user.initials;
user.profileCompletionPercentage;
user.hasCompleteProfile();

```

---

### Validation

This validates not just formats, but also scans the entire user object (including nested addresses and social links) for malicious HTML/XSS injection.


```ts


const result = user.validate();

if (!result.isValid) {
  console.log(result.errors);
}

```
This validates:

- Required fields
- Email format
- Dates
- Phone number format
- Birthdate format

---

### Serialization & Parsing

#### Serialize for storage

```ts


const json = user.toJSON();

```
This output is safe to store in:
- SQL
- NoSQL
- APIs
- Files

#### Parse from JSON

```ts


const user = MajikUser.fromJSON(json);
// or
const user = MajikUser.fromJSON(jsonString);

```

#### Public-safe JSON (no sensitive data)

```ts


const publicUser = user.toPublicJSON();

```

Includes only:
- id
- displayName
- picture
- bio
- createdAt

Perfect for feeds, comments, and public profiles.

---

## Extending Majik User
Majik User is generic-first and designed to be extended.

```ts


interface MyAppUserMetadata extends UserBasicInformation {
  role: "admin" | "user";
  subscriptionTier?: string;
}

class MyAppUser extends MajikUser<MyAppUserMetadata> {}

//Example
const user = MajikUser.initialize<MyAppUserMetadata>(
  "business@thezelijah.world",
  "Zelijah"
);

```
Now your app has a fully typed, domain-safe user model.

---

## Data Integrity & Security

Majik User ensures that your data is not only well-structured but also safe and meaningful across your entire stack.

| Feature                | Description                                                                          |
| :--------------------- | :----------------------------------------------------------------------------------- |
| **Isomorphic**         | Runs everywhere—Works seamlessly in the Browser, Node.js, and Edge Functions.        |
| **Smart Mapping**      | Automatically normalizes messy, flat metadata into structured, nested objects.       |
| **Calculated Getters** | Values like `.age`, `.initials`, and `.isFullyVerified` are computed on the fly.     |
| **XSS-Proof**          | Integrated protection via `DOMPurify` on every setter to block malicious injections. |

---

## Supabase Integration (Optional)

Majik User is designed to sit cleanly **on top of Supabase Auth**, acting as your domain layer while Supabase handles authentication and sessions.

The recommended pattern is:
1. Let Supabase create and authenticate the user
2. Convert the Supabase user → `MajikUser`
3. Store, validate, update, and serialize using `MajikUser`


### Public Signup (POST `/api/users`)

This example shows a **public signup endpoint** using Supabase Auth with email/password, followed by normalization into a `MajikUser`.

```ts


// POST /api/users (Public Signup)
router.post('/', async (request, env: Env): Promise<Response> => {
  console.log('[POST] /users/');

  const errorResponse = await applyMiddleware(request, env);
  if (errorResponse instanceof Response) return errorResponse;

  const body = (await request.json()) as API_SUPABASE_SIGN_UP_BODY;

  if (!body?.email || !body.password || !body?.options?.data) {
    return error('Missing required signup fields', 400, 'MISSING_FIELDS');
  }

  try {
    const supabase = createSupabaseAPIClient(env);

    const { data, error: sbError } =
      await supabase.auth.signUp(body as SignUpWithPasswordCredentials);

    if (sbError) {
      const isDup = sbError.message.includes('already registered');
      return error(
        isDup ? 'This email is already registered.' : sbError.message,
        isDup ? 409 : 400,
        isDup ? 'EMAIL_ALREADY_EXISTS' : undefined,
      );
    }

    // Supabase returns a user even if the email already exists
    if (!data.user?.identities || data.user.identities.length <= 0) {
      return error('Email already exists. Try logging in.', 409, 'EMAIL_ALREADY_EXISTS');
    }

    // Normalize Supabase user → MajikUser
    const userJSON = MajikUser
      .fromSupabase(data.user)
      .toJSON();

    return jsonResponse(
      {
        message: 'Signup successful! Check your email.',
        user: userJSON,
        session: data.session,
        requiresEmailConfirmation: !data.session,
      },
      201,
      corsHeaders,
    );
  } catch {
    return error('Internal server error', 500, 'INTERNAL_ERROR');
  }
});
```

#### Why this works well

- Supabase handles authentication & sessions
- Majik User becomes your single source of truth
- You get validation, normalization, and timestamps for free
- The returned user object is safe to store or cache


### Fetching a User by ID (GET `/api/users/:id`)

This endpoint retrieves a user directly from Supabase Admin, then converts it into a MajikUser.

```ts

// GET /api/users/:id
router.get('/:id', async (request, env: Env): Promise<Response> => {
  console.log('[GET] /users/:id');

  const errorResponse = await applyMiddleware(request, env);
  if (errorResponse instanceof Response) return errorResponse;

  const { id } = request.params;
  const supabase = createSupabaseAPIClient(env);

  const { data, error: sbError } =
    await supabase.auth.admin.getUserById(id);

  if (sbError || !data?.user) {
    return error('User not found', 404, 'USER_NOT_FOUND');
  }

  const userJSON = MajikUser
    .fromSupabase(data.user)
    .toJSON();

  return jsonResponse(userJSON, 200, corsHeaders);
});


```

#### Notes
- Keeps Supabase-specific logic at the edge
- Everything beyond this point deals only with MajikUser
- Ideal for admin panels, dashboards, or internal APIs


### Updating a User (PUT `/api/users/:id`)

This example demonstrates safe user updates using MajikUser validation before writing back to Supabase.

```ts

// PUT /api/users/:id
router.put('/:id', async (request, env: Env): Promise<Response> => {
  console.log('[PUT] /users/:id');

  const errorResponse = await applyMiddleware(request, env);
  if (errorResponse instanceof Response) return errorResponse;

  const { id } = request.params;
  const body = (await request.json()) as MajikUserJSON;

  // Parse incoming data
  const parsedUser = MajikUser.fromJSON(body);

  // Validate before persisting
  const validate = parsedUser.validate();
  if (!validate.isValid) {
    return error('Invalid user data', 400, 'INVALID_USER_DATA');
  }

  const supabase = createSupabaseAPIClient(env);

  // Convert domain object → Supabase-friendly metadata
  const userJSON = parsedUser.toSupabaseJSON();

  const { data, error: sbError } =
    await supabase.auth.admin.updateUserById(id, {
      user_metadata: { ...userJSON },
    });

  if (sbError || !data?.user) {
    console.error('Update error:', sbError);
    return error(sbError?.message || 'Update failed', 400, 'UPDATE_FAILED');
  }

  // Return updated, normalized user
  const newUserJSON = MajikUser
    .fromSupabase(data.user)
    .toJSON();

  return success(
    newUserJSON,
    `Update for ${newUserJSON.email} saved successfully.`,
  );
});


```

#### Why this pattern is recommended
- Incoming data is validated before persistence
- Supabase metadata stays clean and normalized
- No leaking Supabase-specific structures to clients
- MajikUser enforces consistency across all updates

---

## Philosophy


Majik User is:

- ❌ Not an ORM
- ❌ Not an auth system
- ❌ Not a UI state manager

It is:

- A domain model
- A shared contract
- A single source of truth for user behavior


---

## Contributing

If you want to contribute or help extend support to more platforms, reach out via email. All contributions are welcome!  

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/jedlsf/majik-user](https://github.com/jedlsf/majik-user)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
