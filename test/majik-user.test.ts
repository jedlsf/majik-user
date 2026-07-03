import { describe, it, expect, beforeEach } from "vitest";
import { MajikUser } from "../src/core/majik-user";
import { SupabaseUser, UserBasicInformation } from "../src/types";
import { UserGenderOptions } from "../src/enums";

// ==========================================
// MOCK SCHEMA 1: E-Commerce Customer
// ==========================================
interface EcommerceMetadata extends UserBasicInformation {
  stripe_customer_id?: string;
  loyalty_tier?: "Bronze" | "Silver" | "Gold";
  reward_points?: number;
}
class EcommerceUser extends MajikUser<EcommerceMetadata> {}

// ==========================================
// MOCK SCHEMA 2: Gaming Platform Profile
// ==========================================
interface GamerMetadata extends UserBasicInformation {
  gamertag?: string;
  guild_name?: string;
  is_banned?: boolean;
}
class GamerUser extends MajikUser<GamerMetadata> {}

// ==========================================
// MOCK SCHEMA 3: Enterprise / B2B Tenant
// ==========================================
interface B2BMetadata extends UserBasicInformation {
  organization_id?: string;
  clearance_level?: number;
  internal_notes?: string;
}
class B2BUser extends MajikUser<B2BMetadata> {}

describe("MajikUser SDK", () => {
  const XSS_PAYLOADS = [
    "<script>alert('hacked')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert('xss')",
    "Normal text <b onmouseover=alert(1)>with payload</b>",
  ];

  describe("Initialization & Factory Methods", () => {
    it("should initialize a new user correctly", () => {
      const user = MajikUser.initialize("test@example.com", "Test User");
      expect(user.email).toBe("test@example.com");
      expect(user.displayName).toBe("Test User");
      expect(user.id).toBeDefined();
      expect(user.hash).toBeDefined();
      expect(user.createdAt).toBeInstanceOf(Date);
      expect(user.isFullyVerified).toBe(false);
    });

    it("should throw errors for invalid initialization data", () => {
      expect(() => MajikUser.initialize("", "Test User")).toThrow(
        "Email cannot be empty",
      );
      expect(() => MajikUser.initialize("test@example.com", "")).toThrow(
        "Display name cannot be empty",
      );
      expect(() => MajikUser.initialize("invalid-email", "Test User")).toThrow(
        "Invalid email format",
      );
    });

    it("should block XSS payloads in display name during initialization", () => {
      for (const payload of XSS_PAYLOADS) {
        expect(() => MajikUser.initialize("test@example.com", payload)).toThrow(
          "Display name contains suspicious HTML tags",
        );
      }
    });

    it("should initialize from valid JSON", () => {
      const user1 = MajikUser.initialize("json@example.com", "JSON User");
      const jsonStr = JSON.stringify(user1.toJSON());
      const user2 = MajikUser.fromJSON(jsonStr);

      expect(user2.id).toBe(user1.id);
      expect(user2.email).toBe(user1.email);
      expect(user2.displayName).toBe(user1.displayName);
    });

    it("should map Supabase user correctly", () => {
      const supabaseUser: SupabaseUser = {
        id: "supa-123",
        email: "supa@example.com",
        aud: "authenticated",
        created_at: new Date().toISOString(),
        app_metadata: { notifications: false, is_restricted: true },
        user_metadata: {
          first_name: "Supa",
          family_name: "Base",
          gender: UserGenderOptions.MALE,
        },
      };

      const user = MajikUser.fromSupabase(supabaseUser);
      expect(user.id).toBe("supa-123");
      expect(user.email).toBe("supa@example.com");
      expect(user.firstName).toBe("Supa");
      expect(user.lastName).toBe("Base");
      expect(user.gender).toBe(UserGenderOptions.MALE);
      expect(user.settings.notifications).toBe(false);
      expect(user.settings.system.isRestricted).toBe(true);
    });
  });

  describe("Getters and Derived Properties", () => {
    it("should return formatted names correctly", () => {
      const user = MajikUser.initialize("test@example.com", "Fallback Name");
      expect(user.formattedName).toBe("Fallback Name");
      expect(user.fullName).toBeNull();

      user.setName({
        first_name: "John",
        last_name: "Doe",
        middle_name: "Smith",
        suffix: "Jr.",
      });
      expect(user.formattedName).toBe("John Doe");
      expect(user.fullName).toBe("John Smith Doe Jr.");
      expect(user.firstName).toBe("John");
      expect(user.lastName).toBe("Doe");
    });

    it("should calculate initials correctly", () => {
      const user = MajikUser.initialize("test@example.com", "Single");
      expect(user.initials).toBe("SI");

      user.displayName = "Zelijah Dev";
      expect(user.initials).toBe("ZD");

      user.setName({ first_name: "John", last_name: "Doe" });
      expect(user.initials).toBe("JD");
    });

    it("should calculate age correctly", () => {
      const user = MajikUser.initialize("test@example.com", "Age Test");

      const today = new Date();
      const birthYear = today.getFullYear() - 30;

      // Setting birthdate to exactly 30 years ago today
      const birthDate = new Date(birthYear, today.getMonth(), today.getDate());
      user.setBirthdate(birthDate);

      expect(user.age).toBe(30);

      // Setting birthdate to 30 years ago, but tomorrow (meaning they haven't had their birthday yet this year)
      const futureBirthDate = new Date(
        birthYear,
        today.getMonth(),
        today.getDate() + 1,
      );
      user.setBirthdate(futureBirthDate);

      expect(user.age).toBe(29);
    });
  });

  describe("Setters and Anti-XSS Protection", () => {
    let user: MajikUser;

    beforeEach(() => {
      user = MajikUser.initialize("test@example.com", "Test User");
    });

    it("should safely set valid profile fields", () => {
      user.setBio("A regular software engineer.");
      user.setPhone("+1234567890");
      user.setGender(UserGenderOptions.OTHER);

      expect(user.metadata.bio).toBe("A regular software engineer.");
      expect(user.metadata.phone).toBe("+1234567890");
      expect(user.gender).toBe(UserGenderOptions.OTHER);
    });

    it("should unverify fields when changed", () => {
      user.verifyEmail();
      user.verifyPhone();
      expect(user.isEmailVerified).toBe(true);

      user.email = "newemail@example.com";
      expect(user.isEmailVerified).toBe(false);

      user.setPhone("+0987654321");
      expect(user.isPhoneVerified).toBe(false);
    });

    it("should throw errors on XSS in setName", () => {
      for (const payload of XSS_PAYLOADS) {
        expect(() =>
          user.setName({ first_name: payload, last_name: "Doe" }),
        ).toThrow("First name contains suspicious HTML tags");
        expect(() =>
          user.setName({ first_name: "John", last_name: payload }),
        ).toThrow("Last name contains suspicious HTML tags");
      }
    });

    it("should throw errors on XSS in setAddress", () => {
      for (const payload of XSS_PAYLOADS) {
        expect(() => user.setAddress({ street: payload })).toThrow(
          "Address street contains suspicious HTML tags",
        );
      }
    });

    it("should throw errors on XSS in setSocialLink", () => {
      expect(() => user.setSocialLink("X", "javascript:alert(1)")).toThrow(
        "Social link URL contains suspicious HTML tags",
      );
    });

    it("should throw error for unsafe profile picture URLs", () => {
      expect(() => user.setPicture("javascript:alert(1)")).toThrow(
        "Invalid or unsafe URL protocol detected.",
      );
      expect(() => user.setPicture("ftp://malicious.com/payload")).toThrow(
        "Invalid or unsafe URL protocol detected.",
      );

      // Should allow valid URLs
      expect(() =>
        user.setPicture("https://example.com/avatar.png"),
      ).not.toThrow();
      expect(() => user.setPicture("/local/avatar.png")).not.toThrow();
      expect(() =>
        user.setPicture("data:image/png;base64,iVBORw0KGgo..."),
      ).not.toThrow();
    });

    it("should sanitize strings automatically when using setMetadata directly", () => {
      // Because `setMetadata` uses `sanitizeInput` instead of throwing an error:
      user.setMetadata("bio", "I love <script>alert(1)</script> coding.");

      // DOMPurify or the fallback should strip the tags entirely
      expect(user.metadata.bio).not.toContain("<script>");
    });
  });

  describe("Date validations", () => {
    it("should validate and format birthdates properly", () => {
      const user = MajikUser.initialize("test@example.com", "Date Test");

      // Valid YYYY-MM-DD
      user.setBirthdate("1995-12-25");
      expect(user.birthday).toBe("1995-12-25");

      // Valid Date Object
      const d = new Date("1990-01-01T00:00:00Z");
      user.setBirthdate(d);
      expect(user.birthday).toBe("1990-01-01");

      // Invalid formats
      expect(() => user.setBirthdate("12-25-1995" as any)).toThrow(
        "Invalid birthdate format. Use YYYY-MM-DD",
      );
      expect(() => user.setBirthdate(new Date("invalid date"))).toThrow(
        "Invalid Date object",
      );
    });
  });

  describe("Verification & Settings", () => {
    let user: MajikUser;

    beforeEach(() => {
      user = MajikUser.initialize("test@example.com", "Settings User");
    });

    it("should manage verification state", () => {
      expect(user.isFullyVerified).toBe(false);

      user.verifyEmail();
      user.verifyPhone();
      user.verifyIdentity();

      expect(user.isEmailVerified).toBe(true);
      expect(user.isPhoneVerified).toBe(true);
      expect(user.isIdentityVerified).toBe(true);
      expect(user.isFullyVerified).toBe(true);

      user.unverifyIdentity();
      expect(user.isFullyVerified).toBe(false);
    });

    it("should manage restriction state", () => {
      expect(user.isCurrentlyRestricted()).toBe(false);

      // Restrict indefinitely
      user.restrict();
      expect(user.isCurrentlyRestricted()).toBe(true);
      expect(user.settings.system.isRestricted).toBe(true);

      // Unrestrict
      user.unrestrict();
      expect(user.isCurrentlyRestricted()).toBe(false);

      // Restrict in the past (expired)
      const past = new Date(Date.now() - 10000);
      user.restrict(past);
      expect(user.isCurrentlyRestricted()).toBe(false);

      // Restrict in the future (active)
      const future = new Date(Date.now() + 10000);
      user.restrict(future);
      expect(user.isCurrentlyRestricted()).toBe(true);
    });

    it("should toggle notifications", () => {
      user.disableNotifications();
      expect(user.settings.notifications).toBe(false);

      user.enableNotifications();
      expect(user.settings.notifications).toBe(true);
    });
  });

  describe("Utilities and Serialization", () => {
    let user: MajikUser;

    beforeEach(() => {
      user = MajikUser.initialize("test@example.com", "Utility User");
      user.setName({ first_name: "Utility", last_name: "User" });
      user.setBio("Just a test user.");
      user.setPicture("https://example.com/pic.jpg");
    });

    it("should clone properly without reference pollution", () => {
      const clone = user.clone();
      expect(clone.id).toBe(user.id);
      expect(clone.equals(user)).toBe(true);

      clone.displayName = "Cloned User";
      expect(user.displayName).toBe("Utility User"); // Original unharmed
    });

    it("should calculate profile completion percentage", () => {
      // Has name, bio, picture right now. Fields total = 7. 3/7 completed ~ 43%
      const percentage = user.getProfileCompletionPercentage();
      expect(percentage).toBeGreaterThan(0);
      expect(percentage).toBeLessThan(100);

      user.setPhone("+1234567");
      user.setGender(UserGenderOptions.MALE);
      user.setBirthdate("1990-01-01");
      user.setAddress({ city: "Manila", country: "PH" });

      expect(user.getProfileCompletionPercentage()).toBe(100);
      expect(user.hasCompleteProfile()).toBe(true);
    });

    it("should serialize to Public JSON without sensitive data", () => {
      const publicData = user.toPublicJSON();
      expect(publicData.id).toBe(user.id);
      expect(publicData.displayName).toBe("Utility User");
      expect(publicData.bio).toBe("Just a test user.");
      expect(publicData.picture).toBe("https://example.com/pic.jpg");

      // Ensure sensitive data is missing
      expect((publicData as any).email).toBeUndefined();
      expect((publicData as any).hash).toBeUndefined();
      expect((publicData as any).settings).toBeUndefined();
    });

    it("should export to Supabase JSON", () => {
      user.setGender(UserGenderOptions.FEMALE);
      const supabaseData = user.toSupabaseJSON();

      expect(supabaseData.first_name).toBe("Utility");
      expect(supabaseData.family_name).toBe("User");
      expect(supabaseData.display_name).toBe("Utility User");
      expect(supabaseData.gender).toBe(UserGenderOptions.FEMALE);
    });

    it("should fail Supabase export if user data is invalid", () => {
      // Force an invalid state directly via metadata mutation
      (user as any)._email = "invalid-email-format";

      expect(() => user.toSupabaseJSON()).toThrow(
        /Cannot export invalid user data/,
      );
    });

    it("should validate and catch internal errors", () => {
      // Bypassing setters to test the validate() error aggregation directly
      (user as any)._displayName = "<script>bad</script>";
      (user as any)._email = "not-an-email-address"; // Force an invalid email to trigger the second error

      const validation = user.validate();

      expect(validation.isValid).toBe(false);

      // 1. Check if the XSS was caught
      expect(validation.errors).toContain(
        "Suspicious HTML tags detected in displayName",
      );

      // 2. Check if the invalid email was caught
      // The SDK pushes `Invalid email format: ${e}`, so we use .some() to check for inclusion
      expect(
        validation.errors.some((e) => e.includes("Invalid email format")),
      ).toBe(true);

      // 3. Verify that multiple errors were collected
      expect(validation.errors.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("Extended Metadata (Custom Schemas & Deep XSS Protection)", () => {
    // --- Tests --- //

    it("Schema 1: E-Commerce - Should safely store custom fields and sanitize XSS in strings", () => {
      const user = EcommerceUser.initialize(
        "shopper@store.com",
        "Jane Shopper",
      );

      // Set standard non-string custom fields
      user.setMetadata("reward_points", 1500);
      user.setMetadata("loyalty_tier", "Gold");
      expect(user.metadata.reward_points).toBe(1500);
      expect(user.metadata.loyalty_tier).toBe("Gold");

      // Inject XSS into a custom string field
      const maliciousStripeId = "cus_12345<svg onload=alert('steal-card')>";
      user.setMetadata("stripe_customer_id", maliciousStripeId);

      // setMetadata automatically runs sanitizeInput on strings
      expect(user.metadata.stripe_customer_id).not.toContain("<svg");
      expect(user.metadata.stripe_customer_id).not.toContain("onload=");
    });

    it("Schema 2: Gamer Profile - Should handle malformed javascript protocols and boolean properties", () => {
      const user = GamerUser.initialize("player1@gaming.net", "Player One");

      // Set valid boolean
      user.setMetadata("is_banned", true);
      expect(user.metadata.is_banned).toBe(true);

      // Inject malformed javascript URI into a custom field
      const maliciousGamertag = "javascript:alert('xss-exploit')";
      user.setMetadata("gamertag", maliciousGamertag);

      // The sanitizer should strip or neutralize the javascript: protocol
      expect(user.metadata.gamertag).not.toBe(maliciousGamertag);

      // Inject standard XSS payload into guild name
      user.setMetadata(
        "guild_name",
        "Knights of <script>fetch('bad-url')</script> Ni",
      );
      expect(user.metadata.guild_name).not.toContain("<script>");
      expect(user.metadata.guild_name).toContain("Knights of");
    });

    it("Schema 3: Enterprise B2B - Should validate extended instances and catch XSS on updateMetadata", () => {
      const user = B2BUser.initialize("admin@corp.com", "Corp Admin");

      user.setMetadata("organization_id", "ORG-999");
      user.setMetadata("clearance_level", 5);

      expect(user.metadata.organization_id).toBe("ORG-999");
      expect(user.metadata.clearance_level).toBe(5);

      // Test XSS on standard fields while using the extended class
      // Even though it's an extended class, core validations must still apply
      expect(() => {
        user.displayName = "Admin <img src=x onerror=alert('hacked')>";
      }).toThrow("Display name contains suspicious HTML tags");

      // Injecting XSS into custom fields via setMetadata
      user.setMetadata(
        "internal_notes",
        "<iframe src='malicious.com'></iframe> Confidential",
      );
      expect(user.metadata.internal_notes).not.toContain("<iframe");

      // Ensure the cloning mechanism respects the subclass and extended metadata
      const clonedAdmin = user.clone();
      expect(clonedAdmin).toBeInstanceOf(MajikUser);
      expect(clonedAdmin.metadata.organization_id).toBe("ORG-999");
    });

    it("Should successfully serialize and deserialize generic subclasses", () => {
      const originalGamer = GamerUser.initialize("pro@esports.com", "Faker");
      originalGamer.setMetadata("gamertag", "Hide on bush");
      originalGamer.setMetadata("is_banned", false);

      const json = JSON.stringify(originalGamer.toJSON());

      // Rehydrate into the subclass
      const hydratedGamer = GamerUser.fromJSON(json);

      expect(hydratedGamer.email).toBe("pro@esports.com");
      expect(hydratedGamer.metadata.gamertag).toBe("Hide on bush");
      expect(hydratedGamer.metadata.is_banned).toBe(false);
      expect(hydratedGamer).toBeInstanceOf(GamerUser);
    });
  });
});
