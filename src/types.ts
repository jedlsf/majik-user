import type { UserGenderOptions } from "./enums";

export type ISODateString = string;
export type MajikUserID = string;
/**
 * ISO Date string in YYYY-MM-DD format
 */
export type YYYYMMDD = `${number}-${number}-${number}`;

// Make country_code more type-safe
export type CountryCode = string; // Could be literal union of ISO 3166-1 alpha-2 codes

// Make language more type-safe
export type LanguageCode = string; // Could be literal union of ISO 639-1 codes

export interface Address {
  /** Country name */
  country?: string;

  /** City name */
  city?: string;

  /** State or province name */
  region?: string;

  /** Barangay or local area */
  area?: string;

  /** Street address */
  street?: string;

  /** Optional building or suite information */
  building?: string;

  /** Optional postal/zip code */
  zip?: string;

  /** ISO 3166-1 alpha-2 country code (e.g., 'US', 'PH') */
  country_code?: CountryCode;

  /** Geographic coordinates */
  coordinates?: {
    /** Latitude in decimal degrees (-90 to 90) */
    latitude: number;
    /** Longitude in decimal degrees (-180 to 180) */
    longitude: number;
  };
}

/**
 * Stores the user's personal and contact details, including demographics and device information.
 */
export interface UserBasicInformation {
  /** Raw name of the customer */
  name?: FullName;

  /** Profile photo URL or path for the User */
  picture?: string;

  /** User's phone number for contact or verification */
  phone?: string;

  /** User's gender (e.g., 'male', 'female', 'non-binary', etc.) */
  gender?: UserGenderOptions;

  /** User's birthdate in ISO 8601 format (YYYY-MM-DD) */
  birthdate?: YYYYMMDD;

  /** Default address information */
  address?: Address;

  /** User's preferred pronouns */
  pronouns?: string;

  /** Short bio or description */
  bio?: string;

  /** Preferred language code (ISO 639-1, e.g., 'en', 'es') */
  language?: string;

  /** Timezone identifier (e.g., 'Asia/Manila', 'America/New_York') */
  timezone?: string;

  /** Verification status flags */
  verification?: {
    email_verified: boolean;
    phone_verified: boolean;
    identity_verified: boolean;
  };

  /** Social media or external profile links */
  social_links?: Record<string, string>; // e.g., { twitter: 'url', linkedin: 'url' }

  /** Company/organization affiliation */
  company?: CompanyInformation;
}

/**
 * Represents a person's full legal or professional name.
 */
export interface FullName {
  /** First or given name of the person */
  first_name: string;

  /** Last or family name of the person */
  last_name: string;

  /** Optional middle name or initial */
  middle_name?: string;

  /** Optional suffix (e.g., Jr., Sr., III) */
  suffix?: string;
}

/**
 * Basic contact details for a person or organization.
 */
export interface ContactInformation {
  /** Email address, if available */
  email?: string;

  /** Phone number, if available */
  phone?: string;

  /** Website URL, if applicable */
  website?: string;
}

/**
 * Information about the company associated with a client.
 */
export interface CompanyInformation {
  /** Name of the company or organization */
  name: string;

  /** The role or position of the client within the company (e.g., CEO, Manager) */
  role: string;

  /** Contact details for the company or representative */
  contact: ContactInformation;

  /** Optional physical or mailing address of the company */
  address?: string;
}

/**
 * JSON representation of a MajikUser for serialization/deserialization
 */
export interface MajikUserJSON<
  TMetadata extends UserBasicInformation = UserBasicInformation,
> {
  id: MajikUserID;
  email: string;
  displayName: string;
  hash: string;
  metadata: TMetadata;
  settings: UserSettings;
  createdAt: string;
  lastUpdate: string;
}

export interface MajikUserPublicJSON {
  id: MajikUserID;
  displayName: string;
  picture?: string;
  bio?: string;
  createdAt: ISODateString;
}

export interface UserSettings {
  notifications: boolean;
  system: {
    isRestricted: boolean;
    restrictedUntil?: Date;
  };

  [key: string]: unknown;
}

// ==================== SUPABASE TYPES ====================

interface SupabaseUserAppMetadata {
  provider?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

interface SupabaseUserMetadata {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

interface Factor {
  /** ID of the factor. */
  id: string;

  /** Friendly name of the factor, useful to disambiguate between multiple factors. */
  friendly_name?: string;

  /**
   * Type of factor. `totp` and `phone` supported with this version
   */
  factor_type: "totp" | "phone" | (string & {});

  /** Factor's status. */
  status: "verified" | "unverified";

  created_at: string;
  updated_at: string;
}

interface SupabaseUserIdentity {
  id: string;
  user_id: string;
  identity_data?: {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    [key: string]: any;
  };
  identity_id: string;
  provider: string;
  created_at?: string;
  last_sign_in_at?: string;
  updated_at?: string;
}

export interface SupabaseUser {
  id: string;
  app_metadata: SupabaseUserAppMetadata;
  user_metadata: SupabaseUserMetadata;
  aud: string;
  confirmation_sent_at?: string;
  recovery_sent_at?: string;
  email_change_sent_at?: string;
  new_email?: string;
  new_phone?: string;
  invited_at?: string;
  action_link?: string;
  email?: string;
  phone?: string;
  created_at: string;
  confirmed_at?: string;
  email_confirmed_at?: string;
  phone_confirmed_at?: string;
  last_sign_in_at?: string;
  role?: string;
  updated_at?: string;
  identities?: SupabaseUserIdentity[];
  is_anonymous?: boolean;
  is_sso_user?: boolean;
  factors?: Factor[];
}
