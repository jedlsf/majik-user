/**
 * Target gender brackets for the audience.
 */
export const UserGenderOptions = {
  MALE: "Male",
  FEMALE: "Female",
  OTHER: "Other",
} as const;

export type UserGenderOptions =
  (typeof UserGenderOptions)[keyof typeof UserGenderOptions];

/**
 * Enum representing different types of social media platforms.
 */
export const SocialLinkType = {
  FACEBOOK: "Facebook",
  X: "X",
  TIKTOK: "Tik-Tok",
  THREADS: "Threads",
  INSTAGRAM: "Instagram",
  YOUTUBE: "Youtube",
  SPOTIFY: "Spotify",
  APPLE_MUSIC: "Apple Music",
  LINKEDIN: "LinkedIn",
  WEBSITE: "Website URL",
} as const;

export type SocialLinkType =
  (typeof SocialLinkType)[keyof typeof SocialLinkType];

export const Visibility = {
  PRIVATE: "Private",
  PUBLIC: "Public",
  LIMITED: "Limited",
  UNLISTED: "Unlisted",
} as const;

export type Visibility = (typeof Visibility)[keyof typeof Visibility];
