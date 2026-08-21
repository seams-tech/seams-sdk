import * as React from 'react';
import { resolveHref } from './siteRouting';

type GoFn = (to: string) => void;

function isModifiedClick(e: React.MouseEvent<any>): boolean {
  return !!(e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0);
}

function navigateInternal(href: string): void {
  const currentHref = window.location.pathname + window.location.search + window.location.hash;
  const target = new URL(href, window.location.origin);
  /* A deployed build hands us absolute hrefs, so compare and push the
     same-origin path rather than the raw string — otherwise the equality test
     below never matches and history fills with absolute duplicates. */
  const nextHref = `${target.pathname}${target.search}${target.hash}`;

  if (currentHref === nextHref) {
    // Allow same-route nav clicks (for routes like /pricing) to reset scroll.
    if (!target.hash) window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
    return;
  }

  window.history.pushState({}, '', nextHref);
  window.dispatchEvent(new Event('site:navigate'));
  if (!target.hash) window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
}

function requiresDocumentNavigation(href: string): boolean {
  const target = new URL(href, window.location.origin);
  /* Same origin means same app. A deployed build resolves internal hrefs
     against VITE_SITE_ORIGIN, so every one of them arrives here absolute —
     testing for a protocol instead of an origin switched client-side routing
     off in staging and production while leaving it working locally. */
  if (target.origin !== window.location.origin) return true;
  const pathname = target.pathname;
  const isConsolePath =
    pathname === '/dashboard' ||
    pathname.startsWith('/dashboard/') ||
    pathname === '/platform' ||
    pathname.startsWith('/platform/');
  return !isConsolePath;
}

export function useSiteRouter(): {
  go: GoFn;
  linkProps: (to: string) => {
    href: string;
    onClick: (e: React.MouseEvent<HTMLAnchorElement>) => void;
  };
} {
  const go = React.useCallback<GoFn>((to: string) => {
    const href = resolveHref(to);
    if (requiresDocumentNavigation(href)) {
      window.location.href = href;
      return;
    }
    navigateInternal(href);
  }, []);

  const linkProps = React.useCallback((to: string) => {
    const href = resolveHref(to);
    return {
      href,
      onClick: (e: React.MouseEvent<HTMLAnchorElement>) => {
        if (isModifiedClick(e)) return;
        const target = (e.currentTarget.getAttribute('target') || '').toLowerCase();
        if (target && target !== '_self') return;
        if (requiresDocumentNavigation(href)) return;
        e.preventDefault();
        navigateInternal(href);
      },
    };
  }, []);

  return { go, linkProps };
}

export default useSiteRouter;
