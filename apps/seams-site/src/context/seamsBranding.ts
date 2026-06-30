import type { SiteTheme } from '@/shared/hooks/useSiteTheme';

export const SEAMS_BRAND_ASSETS = {
  themeMarkDark: '/seams-v9/svg/seams-mark-theme-dark.svg',
  themeMarkLight: '/seams-v9/svg/seams-mark-theme-light.svg',
  wordmarkDark: '/seams-v9/svg/seams-wordmark-theme-dark.svg',
  wordmarkLight: '/seams-v9/svg/seams-wordmark-theme-light.svg',
} as const;

export type SeamsLogoVariant = 'app-icon' | 'transparent-mark' | 'marketing-mark';

export const SEAMS_LOGO_ASSETS: Record<SeamsLogoVariant, Record<SiteTheme, string>> = {
  'app-icon': {
    dark: SEAMS_BRAND_ASSETS.themeMarkDark,
    light: SEAMS_BRAND_ASSETS.themeMarkLight,
  },
  'transparent-mark': {
    dark: SEAMS_BRAND_ASSETS.themeMarkDark,
    light: SEAMS_BRAND_ASSETS.themeMarkLight,
  },
  'marketing-mark': {
    dark: SEAMS_BRAND_ASSETS.themeMarkDark,
    light: SEAMS_BRAND_ASSETS.themeMarkLight,
  },
};

export function resolveSeamsLogoAsset(variant: SeamsLogoVariant, theme: SiteTheme): string {
  return SEAMS_LOGO_ASSETS[variant][theme];
}

export const SEAMS_WORDMARK_ASSETS: Record<SiteTheme, string> = {
  dark: SEAMS_BRAND_ASSETS.wordmarkDark,
  light: SEAMS_BRAND_ASSETS.wordmarkLight,
};

export function resolveSeamsWordmarkAsset(theme: SiteTheme): string {
  return SEAMS_WORDMARK_ASSETS[theme];
}
