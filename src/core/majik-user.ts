import { arrayToBase64, dateToYYYYMMDD, stripUndefined } from "../utils.js";

import { v4 as uuidv4 } from "uuid";
import { hash } from "@stablelib/sha256";

import type {
  UserBasicInformation,
  FullName,
  Address,
  UserSettings,
  MajikUserJSON,
  SupabaseUser,
  YYYYMMDD,
  MajikUserPublicJSON,
} from "../types.js";
import { UserGenderOptions } from "../enums.js";
import {
  assertSafeObjectKey,
  checkForHTMLTags,
  deepSanitize,
  isPlainObject,
  sanitizeInput,
} from "./sanitize.js";

// Make MajikUser generic to accept extended metadata
export interface MajikUserData<
  TMetadata extends UserBasicInformation = UserBasicInformation,
> {
  id: string;
  email: string;
  displayName: string;
  hash: string;
  metadata: TMetadata;
  settings: UserSettings;
  createdAt: Date;
  lastUpdate: Date;
}

/**
 * Base user class for database persistence
 * Designed to be extended by subclasses with additional metadata
 */
export class MajikUser<
  TMetadata extends UserBasicInformation = UserBasicInformation,
> {
  private readonly _id: string;

  protected _email: string;
  protected _displayName: string;
  protected _hash: string;
  protected _metadata: TMetadata;
  protected _settings: UserSettings;
  private readonly _createdAt: Date;
  protected _lastUpdate: Date;

  constructor(data: MajikUserData<TMetadata>) {
    if (!data || typeof data !== "object") {
      throw new Error("Invalid user data");
    }

    const normalized: any = {
      id: data.id,
      email: data.email,
      displayName: data.displayName,
      hash: data.hash,
      metadata: data.metadata ?? {},
      settings: data.settings ?? {
        notifications: true,
        system: {
          isRestricted: false,
        },
      },
      createdAt: data.createdAt,
      lastUpdate: data.lastUpdate,
    };

    MajikUser.validateAndSanitizeUserData(normalized, true);

    this._id = normalized.id;
    this._email = normalized.email;
    this._displayName = normalized.displayName;
    this._hash = normalized.hash;

    this._metadata = deepSanitize(normalized.metadata) as TMetadata;

    this._settings = deepSanitize(normalized.settings) as UserSettings;

    this._createdAt = new Date(normalized.createdAt);
    this._lastUpdate = new Date(normalized.lastUpdate);
  }

  get id(): string {
    return this._id;
  }

  get createdAt(): Date {
    return new Date(this._createdAt.getTime());
  }

  // ==================== STATIC FACTORY METHODS ====================

  /**
   * Initialize a new user with email and display name
   * Generates a UUID for the id if unset and sets timestamps
   */
  static initialize<T extends MajikUser>(
    this: new (data: MajikUserData<any>) => T,
    email: string,
    displayName: string,
    id?: string,
  ): T {
    if (!email) {
      throw new Error("Email cannot be empty");
    }
    if (!displayName) {
      throw new Error("Display name cannot be empty");
    }

    if (checkForHTMLTags(displayName)) {
      throw new Error("Display name contains suspicious HTML tags");
    }

    const userID = !id?.trim() ? MajikUser.generateID() : id;

    const instance = new this({
      id: userID,
      email,
      displayName,
      hash: MajikUser.hashID(userID),
      metadata: {
        verification: {
          email_verified: false,
          phone_verified: false,
          identity_verified: false,
        },
      },
      settings: {
        notifications: true,
        system: {
          isRestricted: false,
        },
      },
      createdAt: new Date(),
      lastUpdate: new Date(),
    });

    instance.validateEmail(email);
    return instance;
  }

  /**
   * Deserialize user from JSON object or JSON string
   */
  static fromJSON<T extends MajikUser>(
    this: new (data: MajikUserData<any>) => T,
    json: MajikUserJSON<any> | string,
  ): T {
    let data: any;

    try {
      data = typeof json === "string" ? JSON.parse(json) : json;
    } catch {
      throw new Error("Invalid user JSON");
    }

    if (data === null || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("Invalid user data");
    }

    if (typeof data.id !== "string" || !data.id) {
      throw new Error("Invalid user data: missing or invalid id");
    }

    if (typeof data.email !== "string" || !data.email) {
      throw new Error("Invalid user data: missing or invalid email");
    }

    if (typeof data.displayName !== "string" || !data.displayName) {
      throw new Error("Invalid user data: missing or invalid displayName");
    }

    if (typeof data.hash !== "string" || !data.hash) {
      throw new Error("Invalid user data: missing or invalid hash");
    }

    /*
     * Explicitly reject malformed metadata/settings.
     * Arrays are NOT acceptable containers.
     */
    if (data.metadata !== undefined && !isPlainObject(data.metadata)) {
      throw new Error("Invalid metadata object");
    }

    if (data.settings !== undefined && !isPlainObject(data.settings)) {
      throw new Error("Invalid settings object");
    }

    MajikUser.validateIDValue(data.id);
    MajikUser.validateEmailValue(data.email);

    const expectedHash = MajikUser.hashID(data.id);

    if (data.hash !== expectedHash) {
      throw new Error("Invalid user data: hash mismatch");
    }

    const createdAt =
      data.createdAt === undefined ? new Date() : new Date(data.createdAt);

    if (Number.isNaN(createdAt.getTime())) {
      throw new Error("Invalid createdAt date");
    }

    const lastUpdate =
      data.lastUpdate === undefined ? new Date() : new Date(data.lastUpdate);

    if (Number.isNaN(lastUpdate.getTime())) {
      throw new Error("Invalid lastUpdate date");
    }

    const metadata = data.metadata ?? {};

    const settings = data.settings ?? {
      notifications: true,
      system: {
        isRestricted: false,
      },
    };

    const userData: MajikUserData<any> = {
      id: data.id,
      email: data.email,

      /*
       * Deserialized data is untrusted.
       * Sanitize displayName before it reaches state.
       */
      displayName: sanitizeInput(data.displayName),

      hash: data.hash,

      metadata: deepSanitize(metadata),

      settings: deepSanitize(settings),

      createdAt,
      lastUpdate,
    };

    if (!userData.displayName.trim()) {
      throw new Error("Display name cannot be empty");
    }

    MajikUser.validateAndSanitizeUserData(userData, true);

    return new this(userData);
  }

  /**
   * Create MajikUser from Supabase User object
   * Maps Supabase user fields to MajikUser structure
   */
  static fromSupabase<T extends MajikUser>(
    this: new (data: MajikUserData<any>) => T,
    supabaseUser: SupabaseUser,
  ): T {
    if (!supabaseUser.id) {
      throw new Error("Invalid Supabase user: missing id");
    }
    if (!supabaseUser.email) {
      throw new Error("Invalid Supabase user: missing email");
    }

    // Extract display name from user_metadata or email
    const displayName =
      supabaseUser.user_metadata?.display_name ||
      supabaseUser.user_metadata?.full_name ||
      supabaseUser.user_metadata?.name ||
      supabaseUser.email.split("@")[0];

    // Map user_metadata to MajikUser metadata
    const metadata: any = {
      verification: {
        email_verified: !!supabaseUser.email_confirmed_at,
        phone_verified: !!supabaseUser.phone_confirmed_at,
        identity_verified: false,
      },
    };

    // Map optional fields from user_metadata if they exist
    if (supabaseUser.user_metadata) {
      const userMeta = supabaseUser.user_metadata;

      // Name mapping
      if (userMeta.first_name || userMeta.family_name) {
        metadata.name = {
          first_name: userMeta.first_name || "",
          last_name: userMeta.family_name || "",
          middle_name: userMeta.middle_name,
          suffix: userMeta.suffix,
        };
      }

      // Direct field mappings
      if (userMeta.picture || userMeta.avatar_url) {
        metadata.picture = userMeta.picture || userMeta.avatar_url;
      }
      if (userMeta.bio) metadata.bio = userMeta.bio;
      if (userMeta.phone) metadata.phone = userMeta.phone;
      if (userMeta.gender) metadata.gender = userMeta.gender;
      if (userMeta.birthdate) metadata.birthdate = userMeta.birthdate;
      if (userMeta.language) metadata.language = userMeta.language;
      if (userMeta.timezone) metadata.timezone = userMeta.timezone;
      if (userMeta.pronouns) metadata.pronouns = userMeta.pronouns;

      // Address mapping
      if (userMeta.address) {
        metadata.address = userMeta.address;
      }

      // Social links mapping
      if (userMeta.social_links) {
        metadata.social_links = userMeta.social_links;
      }

      // Company information
      if (userMeta.company) {
        metadata.company = userMeta.company;
      }
    }

    // Map app_metadata to settings
    const settings: UserSettings = {
      notifications: supabaseUser.app_metadata?.notifications ?? true,
      system: {
        isRestricted: supabaseUser.app_metadata?.is_restricted ?? false,
        restrictedUntil: supabaseUser.app_metadata?.restricted_until
          ? new Date(supabaseUser.app_metadata.restricted_until)
          : undefined,
      },
    };

    // Add any additional app_metadata to settings
    if (supabaseUser.app_metadata) {
      Object.keys(supabaseUser.app_metadata).forEach((key) => {
        if (
          !["notifications", "is_restricted", "restricted_until"].includes(key)
        ) {
          settings[key] = supabaseUser.app_metadata[key];
        }
      });
    }

    const userData = {
      id: supabaseUser.id,
      email: supabaseUser.email,
      displayName,
      hash: MajikUser.hashID(supabaseUser.id),
      metadata,
      settings,
      createdAt: new Date(supabaseUser.created_at),
      lastUpdate: new Date(supabaseUser.updated_at || supabaseUser.created_at),
    };

    MajikUser.validateAndSanitizeUserData(userData);

    return new this(userData);
  }

  // ==================== GETTERS ====================

  get email(): string {
    return this._email;
  }

  get displayName(): string {
    return this._displayName;
  }

  get hash(): string {
    return this._hash;
  }

  get metadata(): Readonly<TMetadata> {
    return deepSanitize(this._metadata);
  }

  get settings(): Readonly<UserSettings> {
    return deepSanitize(this._settings);
  }

  get lastUpdate(): Date {
    return new Date(this._lastUpdate);
  }

  /**
   * Get user's full name if available
   */
  get fullName(): string | null {
    if (!this._metadata.name) return null;

    const { first_name, middle_name, last_name, suffix } = this._metadata.name;
    const parts = [first_name, middle_name, last_name, suffix].filter(Boolean);
    return parts.join(" ");
  }

  get fullNameObject(): FullName | null {
    if (!this._metadata.name) {
      return null;
    }

    return deepSanitize(this._metadata.name);
  }

  set fullNameObject(name: FullName) {
    if (!name || !name?.first_name?.trim() || !name?.last_name?.trim()) {
      throw new Error("Full name must contain first and last names");
    }

    // ADD THIS:
    if (checkForHTMLTags(name.first_name)) {
      throw new Error("First name contains suspicious HTML tags");
    }
    if (checkForHTMLTags(name.last_name)) {
      throw new Error("Last name contains suspicious HTML tags");
    }
    if (name.middle_name && checkForHTMLTags(name.middle_name)) {
      throw new Error("Middle name contains suspicious HTML tags");
    }
    if (name.suffix && checkForHTMLTags(name.suffix)) {
      throw new Error("Suffix contains suspicious HTML tags");
    }

    this._metadata.name = name;
    this.updateTimestamp();
  }

  /**
   * Get user's formatted name (first + last)
   */
  get formattedName(): string {
    if (!this._metadata.name) return this._displayName;

    const { first_name, last_name } = this._metadata.name;
    if (first_name && last_name) {
      return `${first_name} ${last_name}`;
    }
    return this._displayName;
  }

  /**
   * Get user's first name if available
   */
  get firstName(): string | null {
    if (!this._metadata?.name?.first_name?.trim()) return null;
    return this._metadata.name.first_name;
  }

  /**
   * Get user's last name if available
   */
  get lastName(): string | null {
    if (!this._metadata?.name?.last_name?.trim()) return null;
    return this._metadata.name.last_name;
  }

  /**
   * Get user's gender
   */
  get gender(): string | null {
    if (!this._metadata?.gender?.trim()) return null;
    return this._metadata.gender;
  }

  /**
   * Calculate user's age from birthdate
   */
  get age(): number | null {
    const birthdate = this._metadata.birthdate;
    if (!birthdate) return null;

    const today = new Date();
    const birth = new Date(birthdate);

    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();

    if (
      monthDiff < 0 ||
      (monthDiff === 0 && today.getDate() < birth.getDate())
    ) {
      age--;
    }

    return age;
  }

  /**
   * Get user's first name if available
   */
  get birthday(): YYYYMMDD | null {
    if (!this._metadata?.birthdate?.trim()) return null;
    return this._metadata.birthdate;
  }

  /**
   * Get user's full address if available
   */
  get address(): string | null {
    if (!this._metadata.address) return null;

    const { building, street, area, city, region, zip, country } =
      this._metadata.address;
    const parts = [building, street, area, city, region, zip, country].filter(
      Boolean,
    );
    return parts.join(", ");
  }

  /**
   * Check if email is verified
   */
  get isEmailVerified(): boolean {
    return this._metadata.verification?.email_verified ?? false;
  }

  /**
   * Check if phone is verified
   */
  get isPhoneVerified(): boolean {
    return this._metadata.verification?.phone_verified ?? false;
  }

  /**
   * Check if identity is verified
   */
  get isIdentityVerified(): boolean {
    return this._metadata.verification?.identity_verified ?? false;
  }

  /**
   * Check if all verification steps are complete
   */
  get isFullyVerified(): boolean {
    return (
      this.isEmailVerified && this.isPhoneVerified && this.isIdentityVerified
    );
  }

  /**
   * Get user's initials from name or display name
   */
  get initials(): string {
    if (this._metadata.name) {
      const { first_name, last_name } = this._metadata.name;
      const firstInitial = first_name?.[0]?.toUpperCase() || "";
      const lastInitial = last_name?.[0]?.toUpperCase() || "";
      return (
        `${firstInitial}${lastInitial}`.trim() ||
        this._displayName[0].toUpperCase()
      );
    }

    const names = this._displayName.split(" ");
    if (names.length >= 2) {
      return `${names[0][0]}${names[names.length - 1][0]}`.toUpperCase();
    }
    return this._displayName.slice(0, 2).toUpperCase();
  }

  // ==================== SETTERS ====================

  set email(value: string) {
    this.validateEmail(value);
    this._email = value;
    // Unverify email when changed
    if (this._metadata.verification) {
      this._metadata.verification.email_verified = false;
    }
    this.updateTimestamp();
  }

  set displayName(value: string) {
    if (!value || value.trim().length === 0) {
      throw new Error("Display name cannot be empty");
    }

    if (checkForHTMLTags(value)) {
      throw new Error("Display name contains suspicious HTML tags");
    }
    this._displayName = value;
    this.updateTimestamp();
  }

  set hash(value: string) {
    if (!value || typeof value !== "string") {
      throw new Error("Hash cannot be empty");
    }

    const expected = MajikUser.hashID(this._id);

    if (value !== expected) {
      throw new Error("Hash does not match user ID");
    }

    this._hash = value;
    this.updateTimestamp();
  }
  // ==================== METADATA METHODS ====================

  /**
   * Update user's full name
   */
  setName(name: FullName): void {
    // Validate for HTML tags in all name fields
    if (name.first_name && checkForHTMLTags(name.first_name)) {
      throw new Error("First name contains suspicious HTML tags");
    }
    if (name.last_name && checkForHTMLTags(name.last_name)) {
      throw new Error("Last name contains suspicious HTML tags");
    }
    if (name.middle_name && checkForHTMLTags(name.middle_name)) {
      throw new Error("Middle name contains suspicious HTML tags");
    }
    if (name.suffix && checkForHTMLTags(name.suffix)) {
      throw new Error("Suffix contains suspicious HTML tags");
    }
    this.updateMetadata({ name } as Partial<TMetadata>);
  }

  /**
   * Update user's profile picture
   */
  setPicture(url: string): void {
    if (typeof url !== "string") {
      throw new Error("Invalid picture URL");
    }

    /*
     * Validate the original URL before any generic text
     * sanitizer is applied.
     */
    MajikUser.validatePictureURL(url);

    /*
     * Do not pass an allowed raster data URI through the
     * generic data: protocol sanitizer.
     */
    this._metadata.picture = url as TMetadata[Extract<
      keyof TMetadata,
      "picture"
    >];

    this.updateTimestamp();
  }
  /**
   * Update user's phone number
   */
  setPhone(phone: string): void {
    this.updateMetadata({ phone } as Partial<TMetadata>);
    // Unverify phone when changed
    if (this._metadata.verification) {
      this._metadata.verification.phone_verified = false;
    }
  }

  /**
   * Update user's address
   */
  setAddress(address: Address): void {
    // Validate all address string fields for HTML tags
    const addressFields = [
      { name: "building", value: address.building },
      { name: "street", value: address.street },
      { name: "area", value: address.area },
      { name: "city", value: address.city },
      { name: "region", value: address.region },
      { name: "country", value: address.country },
    ];

    for (const { name, value } of addressFields) {
      if (value && checkForHTMLTags(value)) {
        throw new Error(`Address ${name} contains suspicious HTML tags`);
      }
    }
    this.updateMetadata({ address } as Partial<TMetadata>);
  }

  /**
   * Update user's birthdate
   * Accepts either YYYY-MM-DD string or Date object
   */
  setBirthdate(birthdate: YYYYMMDD | Date): void {
    let formatted: string;

    if (birthdate instanceof Date) {
      if (Number.isNaN(birthdate.getTime())) {
        throw new Error("Invalid Date object");
      }

      // Format to YYYY-MM-DD (UTC-safe)
      formatted = dateToYYYYMMDD(birthdate);
    } else {
      // Validate ISO date format YYYY-MM-DD
      if (!/^\d{4}-\d{2}-\d{2}$/.test(birthdate)) {
        throw new Error("Invalid birthdate format. Use YYYY-MM-DD");
      }

      formatted = birthdate;
    }

    this.updateMetadata({ birthdate: formatted } as Partial<TMetadata>);
  }

  /**
   * Update user's address
   */
  setGender(gender: UserGenderOptions): void {
    if (!Object.values(UserGenderOptions).includes(gender as any)) {
      throw new Error("Invalid gender");
    }

    this.updateMetadata({
      gender,
    } as Partial<TMetadata>);
  }

  /**
   * Update user's bio
   */
  setBio(bio: string): void {
    if (bio && checkForHTMLTags(bio)) {
      throw new Error("Bio contains suspicious HTML tags");
    }
    this.updateMetadata({ bio } as Partial<TMetadata>);
  }

  /**
   * Update user's language preference
   */
  setLanguage(language: string): void {
    if (language && checkForHTMLTags(language)) {
      throw new Error("Language contains suspicious HTML tags");
    }
    this.updateMetadata({ language } as Partial<TMetadata>);
  }

  /**
   * Update user's timezone
   */
  setTimezone(timezone: string): void {
    if (timezone && checkForHTMLTags(timezone)) {
      throw new Error("Timezone contains suspicious HTML tags");
    }
    this.updateMetadata({ timezone } as Partial<TMetadata>);
  }

  /**
   * Add or update a social link
   */
  setSocialLink(platform: string, url: string): void {
    if (platform && checkForHTMLTags(platform)) {
      throw new Error(
        "Social link platform name contains suspicious HTML tags",
      );
    }
    if (url && checkForHTMLTags(url)) {
      throw new Error("Social link URL contains suspicious HTML tags");
    }
    const socialLinks = { ...this._metadata.social_links, [platform]: url };
    this.updateMetadata({ social_links: socialLinks } as Partial<TMetadata>);
  }

  /**
   * Remove a social link
   */
  removeSocialLink(platform: string): void {
    if (!this._metadata.social_links) return;

    const socialLinks = { ...this._metadata.social_links };
    delete socialLinks[platform];
    this.updateMetadata({ social_links: socialLinks } as Partial<TMetadata>);
  }

  /**
   * Update a specific metadata field
   */
  setMetadata(key: keyof TMetadata, value: TMetadata[typeof key]): void {
    if (typeof key !== "string") {
      throw new Error("Metadata key must be a string");
    }

    assertSafeObjectKey(key);

    // Verification state is security-sensitive and must only be changed
    // through the dedicated verification methods.
    if (key === "verification") {
      throw new Error(
        "Verification metadata cannot be modified through setMetadata",
      );
    }

    const safeValue = deepSanitize(value);

    if (key === "picture" && typeof safeValue === "string") {
      MajikUser.validatePictureURL(safeValue);
    }

    if (key === "social_links") {
      MajikUser.validateSocialLinks(safeValue);
    }

    this._metadata[key] = safeValue as TMetadata[typeof key];
    this.updateTimestamp();
  }

  /**
   * Merge multiple metadata fields
   */
  updateMetadata(updates: Partial<TMetadata>): void {
    if (!updates || typeof updates !== "object" || Array.isArray(updates)) {
      throw new Error("Metadata updates must be a plain object");
    }

    for (const key of Object.keys(updates)) {
      assertSafeObjectKey(key);

      if (key === "verification") {
        throw new Error(
          "Verification metadata cannot be modified through updateMetadata",
        );
      }
    }

    const safeUpdates: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(updates)) {
      /*
       * Picture gets specialized URL validation.
       */
      if (key === "picture") {
        if (typeof value !== "string") {
          throw new Error("Invalid picture URL");
        }

        MajikUser.validatePictureURL(value);

        safeUpdates[key] = value;
        continue;
      }

      /*
       * Everything else receives recursive sanitization.
       */
      safeUpdates[key] = deepSanitize(value);
    }

    if (Object.prototype.hasOwnProperty.call(safeUpdates, "social_links")) {
      MajikUser.validateSocialLinks(safeUpdates.social_links);
    }

    this._metadata = {
      ...this._metadata,
      ...(safeUpdates as Partial<TMetadata>),
    };

    this.updateTimestamp();
  }

  // ==================== VERIFICATION METHODS ====================

  private updateVerificationState(
    patch: Partial<{
      email_verified: boolean;
      phone_verified: boolean;
      identity_verified: boolean;
    }>,
  ): void {
    const current = this._metadata.verification ?? {
      email_verified: false,
      phone_verified: false,
      identity_verified: false,
    };

    this._metadata = {
      ...this._metadata,
      verification: {
        ...current,
        ...patch,
      },
    } as TMetadata;

    this.updateTimestamp();
  }

  verifyEmail(): void {
    this.updateVerificationState({
      email_verified: true,
    });
  }

  unverifyEmail(): void {
    this.updateVerificationState({
      email_verified: false,
    });
  }

  verifyPhone(): void {
    this.updateVerificationState({
      phone_verified: true,
    });
  }

  unverifyPhone(): void {
    this.updateVerificationState({
      phone_verified: false,
    });
  }

  verifyIdentity(): void {
    this.updateVerificationState({
      identity_verified: true,
    });
  }

  unverifyIdentity(): void {
    this.updateVerificationState({
      identity_verified: false,
    });
  }

  // ==================== SETTINGS METHODS ====================

  /**
   * Update a specific setting
   */
  setSetting(key: string, value: unknown): void {
    if (typeof key !== "string" || key.length === 0) {
      throw new Error("Setting key must be a non-empty string");
    }

    assertSafeObjectKey(key);

    const safeValue = deepSanitize(value);

    this._settings[key] = safeValue;
    this.updateTimestamp();
  }

  /**
   * Merge multiple settings
   */
  updateSettings(updates: Partial<UserSettings>): void {
    if (!updates || typeof updates !== "object") {
      throw new Error("Settings updates must be an object");
    }

    for (const key of Object.keys(updates)) {
      assertSafeObjectKey(key);
    }

    const safeUpdates = deepSanitize(updates) as Partial<UserSettings>;

    this._settings = {
      ...this._settings,
      ...safeUpdates,
      system: {
        ...this._settings.system,
        ...(safeUpdates.system || {}),
      },
    };

    this.updateTimestamp();
  }

  /**
   * Enable notifications
   */
  enableNotifications(): void {
    this.updateSettings({ notifications: true });
  }

  /**
   * Disable notifications
   */
  disableNotifications(): void {
    this.updateSettings({ notifications: false });
  }

  // ==================== RESTRICTION METHODS ====================

  /**
   * Check if user is currently restricted
   */
  isCurrentlyRestricted(): boolean {
    if (!this._settings.system.isRestricted) return false;
    if (!this._settings.system.restrictedUntil) return true;
    return new Date() < this._settings.system.restrictedUntil;
  }

  /**
   * Restrict user until a specific date (or indefinitely)
   */
  restrict(until?: Date): void {
    this.updateSettings({
      system: {
        isRestricted: true,
        restrictedUntil: until,
      },
    });
  }

  /**
   * Remove restriction from user
   */
  unrestrict(): void {
    this.updateSettings({
      system: {
        isRestricted: false,
        restrictedUntil: undefined,
      },
    });
  }

  // ==================== COMPARISON & UTILITY METHODS ====================

  /**
   * Check if this user has the same ID as another user
   */
  equals(other: MajikUser): boolean {
    return this.id === other.id;
  }

  /**
   * Check if user has complete profile information
   */
  hasCompleteProfile(): boolean {
    return !!(
      this._metadata.name &&
      this._metadata.phone &&
      this._metadata.birthdate &&
      this._metadata.address &&
      this._metadata.gender
    );
  }

  /**
   * Get profile completion percentage (0-100)
   */
  getProfileCompletionPercentage(): number {
    const fields: (keyof TMetadata)[] = [
      "name",
      "picture",
      "phone",
      "gender",
      "birthdate",
      "address",
      "bio",
    ];
    const completedFields = fields.filter((field) => {
      const value = this._metadata[field];
      if (typeof value === "object" && value !== null) {
        return Object.keys(value).length > 0;
      }
      return !!value;
    }).length;

    return Math.round((completedFields / fields.length) * 100);
  }

  // Add detailed validation with error collection
  validate(): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Required fields
    if (!this.id) errors.push("ID is required");
    if (!this._email) errors.push("Email is required");
    if (!this._displayName) errors.push("Display name is required");
    if (!this._hash) errors.push("Hash is required");

    // Format validation
    try {
      this.validateEmail(this._email);
    } catch (e) {
      errors.push(`Invalid email format: ${e}`);
    }

    // Date validation
    if (!(this.createdAt instanceof Date) || isNaN(this.createdAt.getTime())) {
      errors.push("Invalid createdAt date");
    }
    if (
      !(this._lastUpdate instanceof Date) ||
      isNaN(this._lastUpdate.getTime())
    ) {
      errors.push("Invalid lastUpdate date");
    }

    // Metadata validation
    if (this._metadata.phone) {
      if (!/^\+?[1-9]\d{1,14}$/.test(this._metadata.phone)) {
        errors.push("Invalid phone number format");
      }
    }

    if (this._metadata.birthdate) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(this._metadata.birthdate)) {
        errors.push("Invalid birthdate format");
      }
    }

    // HTML/XSS validation for string fields
    const stringFieldsToCheck: { field: string; value: string | undefined }[] =
      [
        { field: "displayName", value: this._displayName },
        { field: "email", value: this._email },
        { field: "bio", value: this._metadata.bio },
        { field: "first_name", value: this._metadata.name?.first_name },
        { field: "last_name", value: this._metadata.name?.last_name },
        { field: "middle_name", value: this._metadata.name?.middle_name },
        { field: "suffix", value: this._metadata.name?.suffix },
      ];

    for (const { field, value } of stringFieldsToCheck) {
      if (value && checkForHTMLTags(value)) {
        errors.push(`Suspicious HTML tags detected in ${field}`);
      }
    }

    // Check address fields for HTML tags
    if (this._metadata.address) {
      const addressFields: { field: string; value: string | undefined }[] = [
        { field: "address.building", value: this._metadata.address.building },
        { field: "address.street", value: this._metadata.address.street },
        { field: "address.area", value: this._metadata.address.area },
        { field: "address.city", value: this._metadata.address.city },
        { field: "address.region", value: this._metadata.address.region },
        { field: "address.country", value: this._metadata.address.country },
      ];

      for (const { field, value } of addressFields) {
        if (value && checkForHTMLTags(value)) {
          errors.push(`Suspicious HTML tags detected in ${field}`);
        }
      }
    }

    // Check social links for suspicious content
    if (this._metadata.social_links) {
      Object.entries(this._metadata.social_links).forEach(([platform, url]) => {
        if (checkForHTMLTags(platform)) {
          errors.push(
            `Suspicious HTML tags detected in social link platform: ${platform}`,
          );
        }
        if (checkForHTMLTags(url)) {
          errors.push(
            `Suspicious HTML tags detected in social link URL for ${platform}`,
          );
        }
      });
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Create a shallow clone of the user
   */
  clone(): MajikUser<TMetadata> {
    return new (this.constructor as typeof MajikUser)({
      id: this.id,
      email: this.email,
      displayName: this.displayName,
      hash: this.hash,
      metadata: deepSanitize(this._metadata),
      settings: deepSanitize(this._settings),
      createdAt: this.createdAt,
      lastUpdate: this.lastUpdate,
    });
  }

  /**
   * Get a supabase ready version of user data (metadata)
   */
  toSupabaseJSON(): Record<string, unknown> {
    const validation = this.validate();
    if (!validation.isValid) {
      throw new Error(
        `Cannot export invalid user data: ${validation.errors.join(", ")}`,
      );
    }

    return stripUndefined({
      age: this.age,
      name: this.fullName,
      gender: this.metadata.gender,
      address: this.metadata.address,
      picture: this.metadata.picture,
      birthdate: this.metadata.birthdate,
      full_name: this.fullName,
      bio: this.metadata.bio,
      first_name: this.metadata.name?.first_name,
      family_name: this.metadata.name?.last_name,
      display_name: this.displayName,
    });
  }

  /**
   * Get a sanitized version of user data (removes sensitive info)
   */
  toPublicJSON(): MajikUserPublicJSON {
    return {
      id: this.id,
      displayName: sanitizeInput(this._displayName),
      picture:
        typeof this._metadata.picture === "string"
          ? sanitizeInput(this._metadata.picture)
          : undefined,
      bio:
        typeof this._metadata.bio === "string"
          ? sanitizeInput(this._metadata.bio)
          : undefined,
      createdAt: this._createdAt.toISOString(),
    };
  }

  /**
   * Serialize user to JSON-compatible object
   */
  toJSON(): MajikUserJSON<TMetadata> {
    MajikUser.validateEmailValue(this._email);

    const expectedHash = MajikUser.hashID(this._id);

    if (this._hash !== expectedHash) {
      throw new Error("User hash integrity check failed");
    }

    if (Number.isNaN(this._createdAt.getTime())) {
      throw new Error("Invalid createdAt date");
    }

    if (Number.isNaN(this._lastUpdate.getTime())) {
      throw new Error("Invalid lastUpdate date");
    }

    return {
      id: this._id,
      email: this._email,
      displayName: sanitizeInput(this._displayName),
      hash: this._hash,
      metadata: deepSanitize(this._metadata),
      settings: deepSanitize(this._settings),
      createdAt: this._createdAt.toISOString(),
      lastUpdate: this._lastUpdate.toISOString(),
    };
  }
  // ==================== PROTECTED HELPER METHODS ====================

  /**
   * Updates the lastUpdate timestamp
   */
  protected updateTimestamp(): void {
    this._lastUpdate = new Date();
  }

  /**
   * Validates email format
   */
  protected validateEmail(email: string): void {
    MajikUser.validateEmailValue(email);
  }

  private static validateEmailValue(email: string): void {
    if (typeof email !== "string" || email.length === 0 || email.length > 254) {
      throw new Error("Invalid email format");
    }

    if (email !== email.trim()) {
      throw new Error("Invalid email format");
    }

    if (/[\r\n\t]/.test(email)) {
      throw new Error("Invalid email format");
    }

    if (checkForHTMLTags(email)) {
      throw new Error("Invalid email format");
    }

    const emailRegex =
      /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;

    if (!emailRegex.test(email)) {
      throw new Error("Invalid email format");
    }
  }

  // ==================== STATIC METHODS ====================

  /**
   * Generate a standard user ID
   */
  protected static generateID(): string {
    try {
      const genID = uuidv4();

      return genID;
    } catch (error) {
      throw new Error(`Failed to generate user ID: ${error}`);
    }
  }

  /**
   * Validate ID format
   */
  protected static validateID(id: string): boolean {
    return /^[A-Za-z0-9+/]+=*$/.test(id) && id.length > 0;
  }

  /**
   * Hash an ID using SHA-256
   */
  protected static hashID(id: string): string {
    const hashedID = hash(new TextEncoder().encode(id));
    return arrayToBase64(hashedID);
  }
  private static validatePictureURL(url: string): void {
    if (!url) {
      return;
    }

    // Local/relative references.
    if (/^(?:\/|#)/.test(url)) {
      return;
    }

    // HTTP(S).
    if (/^https?:\/\//i.test(url)) {
      try {
        const parsed = new URL(url);

        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          throw new Error();
        }

        return;
      } catch {
        throw new Error("Invalid or unsafe URL protocol detected.");
      }
    }

    /*
     * Only permit raster image data URLs.
     *
     * SVG is deliberately excluded because SVG is an
     * active document format and can contain scripting/
     * event-handler content.
     */
    const safeRasterDataUrl =
      /^data:image\/(?:png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/i;

    if (safeRasterDataUrl.test(url)) {
      return;
    }

    throw new Error("Invalid or unsafe URL protocol detected.");
  }

  private static validateSocialLinks(value: unknown): void {
    if (value === undefined) {
      return;
    }

    if (!isPlainObject(value)) {
      throw new Error("Invalid social links object");
    }

    for (const [platform, url] of Object.entries(value)) {
      assertSafeObjectKey(platform);

      if (checkForHTMLTags(platform)) {
        throw new Error("Social link platform contains suspicious content");
      }

      if (typeof url !== "string") {
        throw new Error(`Social link URL for ${platform} must be a string`);
      }

      if (checkForHTMLTags(url)) {
        throw new Error(
          `Social link URL for ${platform} contains suspicious content`,
        );
      }

      if (url && !/^(?:https?:\/\/|\/|#)/i.test(url)) {
        throw new Error(
          `Social link URL for ${platform} uses an unsafe protocol`,
        );
      }
    }
  }

  /**
   * Validate and sanitize user data from external sources
   */
  private static validateAndSanitizeUserData(
    data: Partial<MajikUserData<any>>,
    sanitize = false,
  ): void {
    if (!data || typeof data !== "object") {
      throw new Error("Invalid user data");
    }

    if (typeof data.id !== "string" || !data.id) {
      throw new Error("Invalid user ID");
    }

    MajikUser.validateIDValue(data.id);

    if (typeof data.email !== "string" || !data.email) {
      throw new Error("Invalid email");
    }

    MajikUser.validateEmailValue(data.email);

    if (typeof data.displayName !== "string" || !data.displayName.trim()) {
      throw new Error("Display name cannot be empty");
    }

    if (sanitize) {
      data.displayName = sanitizeInput(data.displayName);
    } else if (checkForHTMLTags(data.displayName)) {
      throw new Error("Display name contains suspicious HTML tags");
    }

    if (typeof data.hash !== "string" || !data.hash) {
      throw new Error("Hash cannot be empty");
    }

    const expectedHash = MajikUser.hashID(data.id);

    if (data.hash !== expectedHash) {
      throw new Error("Hash does not match user ID");
    }

    if (!(data.createdAt instanceof Date)) {
      throw new Error("Invalid createdAt date");
    }

    if (Number.isNaN(data.createdAt.getTime())) {
      throw new Error("Invalid createdAt date");
    }

    if (!(data.lastUpdate instanceof Date)) {
      throw new Error("Invalid lastUpdate date");
    }

    if (Number.isNaN(data.lastUpdate.getTime())) {
      throw new Error("Invalid lastUpdate date");
    }

    if (data.metadata !== undefined && !isPlainObject(data.metadata)) {
      throw new Error("Invalid metadata object");
    }

    if (data.settings !== undefined && !isPlainObject(data.settings)) {
      throw new Error("Invalid settings object");
    }

    if (data.metadata) {
      if (sanitize) {
        data.metadata = deepSanitize(data.metadata);
      } else {
        const safe = deepSanitize(data.metadata);

        if (JSON.stringify(safe) !== JSON.stringify(data.metadata)) {
          throw new Error("Unsafe metadata content detected");
        }
      }
    }

    if (data.settings) {
      if (sanitize) {
        data.settings = deepSanitize(data.settings);
      } else {
        const safe = deepSanitize(data.settings);

        if (JSON.stringify(safe) !== JSON.stringify(data.settings)) {
          throw new Error("Unsafe settings content detected");
        }
      }
    }

    const metadata: any = data.metadata || {};

    // Validate known metadata types.
    for (const field of [
      "bio",
      "picture",
      "phone",
      "language",
      "timezone",
      "gender",
      "pronouns",
    ]) {
      if (
        metadata[field] !== undefined &&
        typeof metadata[field] !== "string"
      ) {
        throw new Error(`Invalid metadata.${field}`);
      }
    }

    if (
      metadata.birthdate !== undefined &&
      typeof metadata.birthdate !== "string"
    ) {
      throw new Error("Invalid birthdate");
    }

    if (metadata.birthdate) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(metadata.birthdate)) {
        throw new Error("Invalid birthdate format");
      }
    }

    if (metadata.picture !== undefined) {
      MajikUser.validatePictureURL(metadata.picture);
    }

    if (metadata.social_links !== undefined) {
      MajikUser.validateSocialLinks(metadata.social_links);
    }

    if (metadata.name !== undefined) {
      if (!isPlainObject(metadata.name)) {
        throw new Error("Invalid metadata.name");
      }

      for (const field of [
        "first_name",
        "last_name",
        "middle_name",
        "suffix",
      ]) {
        if (
          metadata.name[field] !== undefined &&
          typeof metadata.name[field] !== "string"
        ) {
          throw new Error(`Invalid metadata.name.${field}`);
        }
      }
    }

    if (metadata.address !== undefined) {
      if (!isPlainObject(metadata.address)) {
        throw new Error("Invalid metadata.address");
      }

      for (const field of [
        "building",
        "street",
        "area",
        "city",
        "region",
        "zip",
        "country",
      ]) {
        if (
          metadata.address[field] !== undefined &&
          typeof metadata.address[field] !== "string"
        ) {
          throw new Error(`Invalid metadata.address.${field}`);
        }
      }
    }

    if (metadata.verification !== undefined) {
      if (!isPlainObject(metadata.verification)) {
        throw new Error("Invalid verification metadata");
      }

      for (const field of [
        "email_verified",
        "phone_verified",
        "identity_verified",
      ]) {
        if (
          metadata.verification[field] !== undefined &&
          typeof metadata.verification[field] !== "boolean"
        ) {
          throw new Error(`Invalid verification.${field}`);
        }
      }
    }
  }

  private static validateIDValue(id: string): void {
    if (typeof id !== "string" || id.length === 0 || id.length > 256) {
      throw new Error("Invalid user ID");
    }

    if (!/^[A-Za-z0-9][A-Za-z0-9._:@+\/=-]{0,255}$/.test(id)) {
      throw new Error("Invalid user ID");
    }
  }
}
