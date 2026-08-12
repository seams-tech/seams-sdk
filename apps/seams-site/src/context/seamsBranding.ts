export const SEAMS_BRAND_ASSETS = {
  mark: '/seams-v9/svg/seams-mark-mark-transparent-black.svg',
  wordmark: '/seams-v9/svg/seams-wordmark-hanken-dark.svg',
} as const;

export type SeamsLogoVariant = 'app-icon' | 'transparent-mark' | 'marketing-mark';

export function resolveSeamsLogoAsset(_variant: SeamsLogoVariant): string {
  return SEAMS_BRAND_ASSETS.mark;
}

export function resolveSeamsWordmarkAsset(): string {
  return SEAMS_BRAND_ASSETS.wordmark;
}
