export const SEAMS_BRAND_ASSETS = {
  appIcon128: '/seams6_branding_assets/web/seams-icon-128x128.png',
  appIcon180: '/seams6_branding_assets/web/seams-icon-180x180.png',
  appIcon192: '/seams6_branding_assets/web/seams-icon-192x192.png',
  appIcon512: '/seams6_branding_assets/web/seams-icon-512x512.png',
  transparentMark512:
    '/seams6_branding_assets/transparent_mark/Seams_Monogram_Black_Transparent_512.png',
  marketingMark1024: '/seams6_branding_assets/marketing/Seams_Mark_1024x1024_cream.png',
} as const;

export type SeamsLogoVariant = 'app-icon' | 'transparent-mark' | 'marketing-mark';

export const SEAMS_LOGO_ASSETS: Record<SeamsLogoVariant, string> = {
  'app-icon': SEAMS_BRAND_ASSETS.appIcon128,
  'transparent-mark': SEAMS_BRAND_ASSETS.transparentMark512,
  'marketing-mark': SEAMS_BRAND_ASSETS.marketingMark1024,
};
