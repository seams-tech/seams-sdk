export type SiteTheme = 'light';

export function getSiteTheme(): SiteTheme {
  return 'light';
}

export function useSiteTheme(): { theme: SiteTheme } {
  return { theme: 'light' };
}

export default useSiteTheme;
