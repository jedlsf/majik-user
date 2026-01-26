/**
 * Target gender brackets for the audience.
 */
export const UserGenderOptions = {
  MALE: 'Male',
  FEMALE: 'Female',
  OTHER: 'Other'
} as const

export type UserGenderOptions = (typeof UserGenderOptions)[keyof typeof UserGenderOptions]

/**
 * Enum representing different types of social media platforms.
 */
export const SocialLinkType = {
  FACEBOOK: 'Facebook',
  X: 'X',
  TIKTOK: 'Tik-Tok',
  THREADS: 'Threads',
  INSTAGRAM: 'Instagram',
  YOUTUBE: 'Youtube',
  SPOTIFY: 'Spotify',
  APPLE_MUSIC: 'Apple Music',
  LINKEDIN: 'LinkedIn',
  WEBSITE: 'Website URL'
} as const

export type SocialLinkType = (typeof SocialLinkType)[keyof typeof SocialLinkType]

/** Payment methods accepted for the invoice */
export const PaymentMethod = {
  /** Payment is made in cash */
  CASH: 'Cash',
  /** Payment is made via bank transfer or deposit */
  BANK: 'Bank',
  /** Payment is made via e-wallet transfer */
  EWALLET: 'E-Wallet',
  /** Payment is made using a check */
  CHECK: 'Check'
} as const

export type PaymentMethod = (typeof PaymentMethod)[keyof typeof PaymentMethod]

export const Visibility = {
  PRIVATE: 'Private',
  PUBLIC: 'Public',
  LIMITED: 'Limited',
  UNLISTED: 'Unlisted'
} as const

export type Visibility = (typeof Visibility)[keyof typeof Visibility]
