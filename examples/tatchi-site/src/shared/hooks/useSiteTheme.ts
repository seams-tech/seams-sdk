import * as React from 'react';

export type SiteTheme = 'light' | 'dark';

const SITE_THEME_KEY = 'tatchi-site-theme';

function readStoredTheme(): SiteTheme | null {
  try {
    const value = window.localStorage?.getItem?.(SITE_THEME_KEY);
    if (value === 'light' || value === 'dark') return value;
  } catch {}
  return null;
}

export function getSiteTheme(): SiteTheme {
  if (typeof window !== 'undefined') {
    const stored = readStoredTheme();
    if (stored) return stored;
  }

  if (typeof document !== 'undefined') {
    const attr = document.documentElement.getAttribute('data-w3a-theme');
    if (attr === 'light' || attr === 'dark') return attr;
    return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
  }

  return 'dark';
}

function applyTheme(next: SiteTheme): void {
  if (typeof window !== 'undefined') {
    try {
      window.localStorage?.setItem?.(SITE_THEME_KEY, next);
    } catch {}
  }

  if (typeof document !== 'undefined') {
    document.documentElement.classList.toggle('dark', next === 'dark');
    document.documentElement.setAttribute('data-w3a-theme', next);
  }

  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('w3a:appearance', { detail: next }));
  }
}

export function useSiteTheme() {
  const [theme, setThemeState] = React.useState<SiteTheme>(() => getSiteTheme());

  const setTheme = React.useCallback((next: SiteTheme) => {
    if (next !== 'light' && next !== 'dark') return;
    setThemeState(next);
  }, []);

  React.useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  React.useEffect(() => {
    if (typeof document === 'undefined') return;
    const read = () => setThemeState(getSiteTheme());
    read();

    const mo = new MutationObserver(() => read());
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

    const onStorage = (e: StorageEvent) => {
      if (e.key !== SITE_THEME_KEY) return;
      const next = e.newValue === 'dark' ? 'dark' : 'light';
      setThemeState(next);
    };
    window.addEventListener('storage', onStorage);

    const onAppearance = (e: Event) => {
      const next = (e as CustomEvent<'light' | 'dark'>)?.detail;
      if (next === 'light' || next === 'dark') setThemeState(next);
    };
    window.addEventListener('w3a:appearance', onAppearance as any);
    window.addEventListener('w3a:set-theme', onAppearance as any);

    return () => {
      mo.disconnect();
      window.removeEventListener('storage', onStorage);
      window.removeEventListener('w3a:appearance', onAppearance as any);
      window.removeEventListener('w3a:set-theme', onAppearance as any);
    };
  }, []);

  return { theme, setTheme };
}

export default useSiteTheme;
