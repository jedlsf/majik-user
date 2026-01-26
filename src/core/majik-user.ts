import { arrayToBase64, dateToYYYYMMDD, stripUndefined } from "../utils";

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
} from "../types";
import type { UserGenderOptions } from "../enums";

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
  readonly id: string;
  protected _email: string;
  protected _displayName: string;
  protected _hash: string;
  protected _metadata: TMetadata;
  protected _settings: UserSettings;
  readonly createdAt: Date;
  protected _lastUpdate: Date;

  constructor(data: MajikUserData<TMetadata>) {
    this.id = data.id;
    this._email = data.email;
    this._displayName = data.displayName;
    this._hash = data.hash;
    this._metadata = { ...data.metadata };
    this._settings = { ...data.settings };
    this.createdAt = new Date(data.createdAt);
    this._lastUpdate = new Date(data.lastUpdate);
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
    // Parse string to object if needed
    const data = typeof json === "string" ? JSON.parse(json) : json;

    if (!data.id || typeof data.id !== "string") {
      throw new Error("Invalid user data: missing or invalid id");
    }
    if (!data.email || typeof data.email !== "string") {
      throw new Error("Invalid user data: missing or invalid email");
    }
    if (!data.displayName || typeof data.displayName !== "string") {
      throw new Error("Invalid user data: missing or invalid displayName");
    }
    if (!data.hash || typeof data.hash !== "string") {
      throw new Error("Invalid user data: missing or invalid hash");
    }

    const userData = {
      id: data.id,
      email: data.email,
      displayName: data.displayName,
      hash: data.hash,
      metadata: data.metadata || {},
      settings: data.settings || {
        notifications: true,
        system: {
          isRestricted: false,
        },
      },
      createdAt: data.createdAt ? new Date(data.createdAt) : new Date(),
      lastUpdate: data.lastUpdate ? new Date(data.lastUpdate) : new Date(),
    };

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
    return { ...this._metadata };
  }

  get settings(): Readonly<UserSettings> {
    return { ...this._settings };
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
    if (!this._metadata.name) return null;
    return this._metadata.name;
  }

  set fullNameObject(name: FullName) {
    if (!name || !name?.first_name?.trim() || !name?.last_name?.trim()) {
      throw new Error("Full name must contain first and last names");
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
    this._displayName = value;
    this.updateTimestamp();
  }

  set hash(value: string) {
    if (!value || value.length === 0) {
      throw new Error("Hash cannot be empty");
    }
    this._hash = value;
    this.updateTimestamp();
  }

  // ==================== METADATA METHODS ====================

  /**
   * Update user's full name
   */
  setName(name: FullName): void {
    this.updateMetadata({ name } as Partial<TMetadata>);
  }

  /**
   * Update user's profile picture
   */
  setPicture(url: string): void {
    this.updateMetadata({ picture: url } as Partial<TMetadata>);
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
    this.updateMetadata({ gender } as Partial<TMetadata>);
  }

  /**
   * Update user's bio
   */
  setBio(bio: string): void {
    this.updateMetadata({ bio } as Partial<TMetadata>);
  }

  /**
   * Update user's language preference
   */
  setLanguage(language: string): void {
    this.updateMetadata({ language } as Partial<TMetadata>);
  }

  /**
   * Update user's timezone
   */
  setTimezone(timezone: string): void {
    this.updateMetadata({ timezone } as Partial<TMetadata>);
  }

  /**
   * Add or update a social link
   */
  setSocialLink(platform: string, url: string): void {
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
    this._metadata[key] = value;
    this.updateTimestamp();
  }
  /**
   * Merge multiple metadata fields
   */
  updateMetadata(updates: Partial<TMetadata>): void {
    this._metadata = { ...this._metadata, ...updates };
    this.updateTimestamp();
  }

  // ==================== VERIFICATION METHODS ====================

  /**
   * Mark email as verified
   */
  verifyEmail(): void {
    const currentVerification = this._metadata.verification || {
      email_verified: false,
      phone_verified: false,
      identity_verified: false,
    };

    this.updateMetadata({
      verification: {
        ...currentVerification,
        email_verified: true,
      },
    } as Partial<TMetadata>);
  }

  /**
   * Mark email as unverified
   */
  unverifyEmail(): void {
    const currentVerification = this._metadata.verification || {
      email_verified: false,
      phone_verified: false,
      identity_verified: false,
    };

    this.updateMetadata({
      verification: {
        ...currentVerification,
        email_verified: false,
      },
    } as Partial<TMetadata>);
  }

  /**
   * Mark phone as verified
   */
  verifyPhone(): void {
    const currentVerification = this._metadata.verification || {
      email_verified: false,
      phone_verified: false,
      identity_verified: false,
    };

    this.updateMetadata({
      verification: {
        ...currentVerification,
        phone_verified: true,
      },
    } as Partial<TMetadata>);
  }

  /**
   * Mark phone as unverified
   */
  unverifyPhone(): void {
    const currentVerification = this._metadata.verification || {
      email_verified: false,
      phone_verified: false,
      identity_verified: false,
    };

    this.updateMetadata({
      verification: {
        ...currentVerification,
        phone_verified: false,
      },
    } as Partial<TMetadata>);
  }

  /**
   * Mark identity as verified (KYC)
   */
  verifyIdentity(): void {
    const currentVerification = this._metadata.verification || {
      email_verified: false,
      phone_verified: false,
      identity_verified: false,
    };

    this.updateMetadata({
      verification: {
        ...currentVerification,
        identity_verified: true,
      },
    } as Partial<TMetadata>);
  }

  /**
   * Mark identity as unverified
   */
  unverifyIdentity(): void {
    const currentVerification = this._metadata.verification || {
      email_verified: false,
      phone_verified: false,
      identity_verified: false,
    };

    this.updateMetadata({
      verification: {
        ...currentVerification,
        identity_verified: false,
      },
    } as Partial<TMetadata>);
  }

  // ==================== SETTINGS METHODS ====================

  /**
   * Update a specific setting
   */
  setSetting(key: string, value: unknown): void {
    this._settings[key] = value;
    this.updateTimestamp();
  }

  /**
   * Merge multiple settings
   */
  updateSettings(updates: Partial<UserSettings>): void {
    this._settings = {
      ...this._settings,
      ...updates,
      system: {
        ...this._settings.system,
        ...(updates.system || {}),
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
      email: this._email,
      displayName: this._displayName,
      hash: this._hash,
      metadata: { ...this._metadata },
      settings: { ...this._settings },
      createdAt: this.createdAt,
      lastUpdate: this._lastUpdate,
    });
  }

  /**
   * Get a supabase ready version of user data (metadata)
   */
  toSupabaseJSON(): Record<string, unknown> {
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
      displayName: this._displayName,
      picture: this._metadata.picture,
      bio: this._metadata.bio,
      createdAt: this.createdAt.toISOString(),
    };
  }

  /**
   * Serialize user to JSON-compatible object
   */
  toJSON(): MajikUserJSON<TMetadata> {
    return {
      id: this.id,
      email: this._email,
      displayName: this._displayName,
      hash: this._hash,
      metadata: { ...this._metadata },
      settings: { ...this._settings },
      createdAt: this.createdAt.toISOString(),
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
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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
}
