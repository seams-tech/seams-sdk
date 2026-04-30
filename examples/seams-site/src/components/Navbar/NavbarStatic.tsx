import React from 'react';
import { ChevronDown, Menu, X } from 'lucide-react';
import { MoonIcon, SunIcon, useTheme } from '@seams/sdk/react';
import { ArrowRightAnim } from '../ArrowRightAnim';
import SeamsLogo from '../icons/SeamsLogo';
import { DashboardGoogleAuthCard } from '@/shared/auth/DashboardGoogleAuthCard';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { FRONTEND_CONFIG } from '@/config';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';
import './Navbar.css';

type DropdownId = 'products' | 'solutions' | 'about';

type DropdownItem = {
  title: string;
  description: string;
  to: string;
};

type DropdownSection = {
  heading: string;
  items: DropdownItem[];
};

type DropdownConfig = {
  id: DropdownId;
  label: string;
  rootTo?: string;
  allLabel?: string;
  sections: DropdownSection[];
};

type DropdownFocusTarget = 'first' | 'last';
const DEFAULT_DROPDOWN_MAX_WIDTH_PX = 820;
const ABOUT_DROPDOWN_MAX_WIDTH_PX = DEFAULT_DROPDOWN_MAX_WIDTH_PX / 2;
const DASHBOARD_AUTH_OPEN_EVENT = 'seams:dashboard-auth-open';

const productSections: DropdownSection[] = [
  {
    heading: 'Wallets',
    items: [
      {
        title: 'Embedded Wallets',
        description: 'Passkey wallet flows that stay inside your app UI',
        to: '/docs/getting-started/overview',
      },
      {
        title: 'Account Sync',
        description: 'Restore and link accounts across devices',
        to: '/docs/concepts/passkey-scope',
      },
    ],
  },
  {
    heading: 'Signing & Security',
    items: [
      {
        title: 'Threshold Signing',
        description: 'Distributed signing with strict policy controls',
        to: '/docs/concepts/threshold-signing',
      },
      {
        title: 'SecureConfirm WebAuthn',
        description: 'Onchain-verifiable confirmation challenges',
        to: '/docs/concepts/secureconfirm-webauthn',
      },
      {
        title: 'Security Model',
        description: 'Defense-in-depth and browser policy boundaries',
        to: '/docs/concepts/security-model',
      },
    ],
  },
];

const solutionSections: DropdownSection[] = [
  {
    heading: 'By Use Case',
    items: [
      {
        title: 'Consumer Apps',
        description: 'Passkey wallets without popups or extension installs',
        to: '/solutions/#consumer-apps',
      },
      {
        title: 'Stablecoin Payments',
        description: 'In-app signing and transaction confirmation flows',
        to: '/solutions/#stablecoin-payments',
      },
      {
        title: 'Treasury & Payouts',
        description: 'Policy-based approvals for internal transfers',
        to: '/solutions/#treasury-and-payouts',
      },
      {
        title: 'Recovery & Device Linking',
        description: 'Cross-device account continuity without seed phrases',
        to: '/solutions/#recovery-and-device-linking',
      },
    ],
  },
  {
    heading: 'By Team',
    items: [
      {
        title: 'Product Teams',
        description: 'Friction-light wallet UX patterns for conversion',
        to: '/solutions/#product-teams',
      },
      {
        title: 'Security Teams',
        description: 'SecureConfirm and threshold policy guardrails',
        to: '/solutions/#security-teams',
      },
      {
        title: 'Platform Teams',
        description: 'Reusable signing primitives across multiple apps',
        to: '/solutions/#platform-teams',
      },
    ],
  },
];

const aboutSections: DropdownSection[] = [
  {
    heading: 'About Us',
    items: [
      {
        title: 'Company',
        description: 'Company details',
        to: '/company/#careers',
      },
      {
        title: 'Blog',
        description: 'Read the latest from our team',
        to: '/company/#blog',
      },
      {
        title: 'Support',
        description: 'Join our developer Slack community',
        to: '/contact/',
      },
    ],
  },
];

const primaryDropdownConfigs: DropdownConfig[] = [
  {
    id: 'products',
    label: 'Products',
    sections: productSections,
  },
  {
    id: 'solutions',
    label: 'Solutions',
    sections: solutionSections,
  },
];

const aboutDropdownConfig: DropdownConfig = {
  id: 'about',
  label: 'About Us',
  rootTo: '/company/',
  allLabel: 'View company overview',
  sections: aboutSections,
};

const dropdownConfigs: DropdownConfig[] = [...primaryDropdownConfigs, aboutDropdownConfig];

function isClickInsideRoot(target: EventTarget | null, root: HTMLElement | null): boolean {
  return !!(target instanceof Node && root && root.contains(target));
}

function getMenuItems(panel: HTMLDivElement | null, id: DropdownId | null): HTMLElement[] {
  if (!panel || !id) return [];
  return Array.from(
    panel.querySelectorAll<HTMLElement>(`[data-dropdown-view="${id}"] a[role="menuitem"]`),
  );
}

function readDocumentTheme(): 'light' | 'dark' {
  if (typeof document === 'undefined') return 'dark';
  const attr = document.documentElement.getAttribute('data-w3a-theme');
  if (attr === 'light' || attr === 'dark') return attr;
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

function applyDocumentTheme(next: 'light' | 'dark'): void {
  if (typeof document === 'undefined' || typeof window === 'undefined') return;
  document.documentElement.classList.toggle('dark', next === 'dark');
  document.documentElement.setAttribute('data-w3a-theme', next);
  try {
    window.localStorage?.setItem?.('seams-site-theme', next);
  } catch {}
  window.dispatchEvent(new CustomEvent<'light' | 'dark'>('w3a:appearance', { detail: next }));
}

function getDropdownMaxWidthPx(id: DropdownId | null): number {
  return id === 'about' ? ABOUT_DROPDOWN_MAX_WIDTH_PX : DEFAULT_DROPDOWN_MAX_WIDTH_PX;
}

interface RelaySessionStateResponse {
  authenticated?: boolean;
  claims?: {
    sub?: string;
    userId?: string;
    provider?: string;
  };
  message?: string;
}

function normalizeBaseUrl(input: unknown): string {
  return String(input || '')
    .trim()
    .replace(/\/+$/, '');
}

async function parseOptionalJson(response: Response): Promise<any> {
  return response.json().catch(() => null);
}

export function NavbarStatic(): React.JSX.Element {
  const OPEN_DELAY_MS = 0;
  const CLOSE_DELAY_MS = 280;
  const CONTENT_SWITCH_MS = 660;
  const SCROLL_THRESHOLD_PX = 8;

  const { theme, setTheme } = useTheme();
  const { go, linkProps } = useSiteRouter();
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.relayerUrl || FRONTEND_CONFIG.consoleBaseUrl),
    [],
  );
  const [googleClientId, setGoogleClientId] = React.useState<string>('');
  const rootRef = React.useRef<HTMLElement | null>(null);
  const shellRef = React.useRef<HTMLDivElement | null>(null);
  const dropdownButtonRefs = React.useRef<Record<DropdownId, HTMLButtonElement | null>>({
    products: null,
    solutions: null,
    about: null,
  });
  const dropdownPanelRef = React.useRef<HTMLDivElement | null>(null);
  const openTimerRef = React.useRef<number | null>(null);
  const closeTimerRef = React.useRef<number | null>(null);
  const switchTimerRef = React.useRef<number | null>(null);
  const [openDropdown, setOpenDropdown] = React.useState<DropdownId | null>(null);
  const [visibleDropdown, setVisibleDropdown] = React.useState<DropdownId | null>(null);
  const [leavingDropdown, setLeavingDropdown] = React.useState<DropdownId | null>(null);
  const [dropdownSurfaceLeft, setDropdownSurfaceLeft] = React.useState<number>(0);
  const [dropdownNotchLeft, setDropdownNotchLeft] = React.useState<number>(120);
  const [hasScrolled, setHasScrolled] = React.useState<boolean>(false);
  const [localTheme, setLocalTheme] = React.useState<'light' | 'dark'>(() => readDocumentTheme());
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState<boolean>(false);
  const [isMobileProductsOpen, setIsMobileProductsOpen] = React.useState<boolean>(false);
  const [isMobileSolutionsOpen, setIsMobileSolutionsOpen] = React.useState<boolean>(false);
  const [isMobileAboutOpen, setIsMobileAboutOpen] = React.useState<boolean>(false);
  const [isDashboardAuthOpen, setIsDashboardAuthOpen] = React.useState<boolean>(false);
  const [dashboardAuthError, setDashboardAuthError] = React.useState<string>('');
  const [relaySessionLoading, setRelaySessionLoading] = React.useState<boolean>(false);
  const [relaySessionAuthenticated, setRelaySessionAuthenticated] = React.useState<boolean>(false);
  const [googleConfigChecked, setGoogleConfigChecked] = React.useState<boolean>(false);
  const [googleConfigured, setGoogleConfigured] = React.useState<boolean>(false);
  const [googleSigningIn, setGoogleSigningIn] = React.useState<boolean>(false);

  const resolvedTheme: 'light' | 'dark' =
    (typeof setTheme === 'function' ? theme : localTheme) === 'dark' ? 'dark' : 'light';

  const onToggleTheme = React.useCallback(() => {
    const next: 'light' | 'dark' = resolvedTheme === 'dark' ? 'light' : 'dark';
    if (typeof setTheme === 'function') {
      setTheme(next);
      return;
    }
    applyDocumentTheme(next);
    setLocalTheme(next);
  }, [resolvedTheme, setTheme]);

  const refreshRelaySessionState = React.useCallback(async (): Promise<boolean> => {
    if (!relayerBaseUrl) {
      setRelaySessionAuthenticated(false);
      return false;
    }
    setRelaySessionLoading(true);
    try {
      const response = await fetch(`${relayerBaseUrl}/session/state`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
        },
        cache: 'no-store',
      });
      const body = (await parseOptionalJson(response)) as RelaySessionStateResponse | null;
      const authenticated = response.ok && body?.authenticated === true;
      setRelaySessionAuthenticated(authenticated);
      return authenticated;
    } catch {
      setRelaySessionAuthenticated(false);
      return false;
    } finally {
      setRelaySessionLoading(false);
    }
  }, [relayerBaseUrl]);

  const refreshGoogleConfigured = React.useCallback(async (): Promise<boolean> => {
    if (!relayerBaseUrl) {
      setGoogleClientId('');
      setGoogleConfigured(false);
      setGoogleConfigChecked(true);
      return false;
    }
    try {
      const options = await fetchGoogleAuthOptions(relayerBaseUrl);
      setGoogleClientId(options.clientId || '');
      setGoogleConfigured(options.configured);
      setGoogleConfigChecked(true);
      return options.configured;
    } catch {
      setGoogleClientId('');
      setGoogleConfigured(false);
      setGoogleConfigChecked(true);
      return false;
    }
  }, [relayerBaseUrl]);

  React.useEffect(() => {
    void refreshRelaySessionState();
  }, [refreshRelaySessionState]);

  const clearDropdownTimers = React.useCallback(() => {
    if (openTimerRef.current !== null) {
      window.clearTimeout(openTimerRef.current);
      openTimerRef.current = null;
    }
    if (closeTimerRef.current !== null) {
      window.clearTimeout(closeTimerRef.current);
      closeTimerRef.current = null;
    }
  }, []);

  const clearContentSwitchTimer = React.useCallback(() => {
    if (switchTimerRef.current !== null) {
      window.clearTimeout(switchTimerRef.current);
      switchTimerRef.current = null;
    }
  }, []);

  const updateDropdownNotchPosition = React.useCallback((id: DropdownId) => {
    const shell = shellRef.current;
    const button = dropdownButtonRefs.current[id];
    if (!shell || !button) return;

    const clamp = (value: number, min: number, max: number): number =>
      Math.min(Math.max(value, min), max);
    const shellRect = shell.getBoundingClientRect();
    const buttonRect = button.getBoundingClientRect();

    const rootFontSize =
      typeof window === 'undefined'
        ? 16
        : Number.parseFloat(window.getComputedStyle(document.documentElement).fontSize) || 16;
    const horizontalInsetPx = rootFontSize * 2; // matches CSS width: calc(100% - 2rem)

    const surfaceWidth = Math.min(
      getDropdownMaxWidthPx(id),
      Math.max(shellRect.width - horizontalInsetPx, 0),
    );
    const triggerCenter = buttonRect.left + buttonRect.width / 2 - shellRect.left;
    const surfaceLeft = clamp(
      triggerCenter - surfaceWidth / 2,
      0,
      Math.max(shellRect.width - surfaceWidth, 0),
    );

    setDropdownSurfaceLeft(surfaceLeft);
    setDropdownNotchLeft(clamp(triggerCenter - surfaceLeft, 42, Math.max(surfaceWidth - 42, 42)));
  }, []);

  const scheduleOpenDropdown = React.useCallback(
    (id: DropdownId, delayMs: number = OPEN_DELAY_MS) => {
      if (isMobileMenuOpen) return;

      const effectiveDelayMs = openDropdown && openDropdown !== id ? 0 : delayMs;

      if (closeTimerRef.current !== null) {
        window.clearTimeout(closeTimerRef.current);
        closeTimerRef.current = null;
      }
      if (openTimerRef.current !== null) {
        window.clearTimeout(openTimerRef.current);
        openTimerRef.current = null;
      }

      openTimerRef.current = window.setTimeout(() => {
        setOpenDropdown(id);
        updateDropdownNotchPosition(id);
        openTimerRef.current = null;
      }, effectiveDelayMs);
    },
    [isMobileMenuOpen, openDropdown, updateDropdownNotchPosition],
  );

  const scheduleCloseDropdown = React.useCallback(
    (delayMs: number = CLOSE_DELAY_MS) => {
      if (isMobileMenuOpen) return;
      if (openTimerRef.current !== null) {
        window.clearTimeout(openTimerRef.current);
        openTimerRef.current = null;
      }
      if (closeTimerRef.current !== null) {
        window.clearTimeout(closeTimerRef.current);
        closeTimerRef.current = null;
      }
      closeTimerRef.current = window.setTimeout(() => {
        setOpenDropdown(null);
        closeTimerRef.current = null;
      }, delayMs);
    },
    [isMobileMenuOpen],
  );

  const closeMenus = React.useCallback(() => {
    clearDropdownTimers();
    clearContentSwitchTimer();
    setOpenDropdown(null);
    setVisibleDropdown(null);
    setLeavingDropdown(null);
    setIsMobileMenuOpen(false);
    setIsMobileProductsOpen(false);
    setIsMobileSolutionsOpen(false);
    setIsMobileAboutOpen(false);
  }, [clearDropdownTimers, clearContentSwitchTimer]);

  React.useEffect(() => {
    return () => {
      clearDropdownTimers();
      clearContentSwitchTimer();
    };
  }, [clearDropdownTimers, clearContentSwitchTimer]);

  React.useEffect(() => {
    const onScroll = () => {
      setHasScrolled(window.scrollY > SCROLL_THRESHOLD_PX);
    };

    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
    };
  }, [SCROLL_THRESHOLD_PX]);

  React.useEffect(() => {
    if (typeof setTheme === 'function') return;
    if (typeof document === 'undefined' || typeof window === 'undefined') return;

    const read = () => setLocalTheme(readDocumentTheme());
    read();

    const mo = new MutationObserver(read);
    mo.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class', 'data-w3a-theme'],
    });

    const onAppearance = (e: Event) => {
      const next = (e as CustomEvent<'light' | 'dark'>)?.detail;
      if (next === 'light' || next === 'dark') setLocalTheme(next);
      else read();
    };

    window.addEventListener('w3a:appearance', onAppearance as EventListener);
    window.addEventListener('w3a:set-theme', onAppearance as EventListener);
    return () => {
      mo.disconnect();
      window.removeEventListener('w3a:appearance', onAppearance as EventListener);
      window.removeEventListener('w3a:set-theme', onAppearance as EventListener);
    };
  }, [setTheme]);

  React.useEffect(() => {
    clearContentSwitchTimer();

    if (!openDropdown) {
      setLeavingDropdown(null);
      setVisibleDropdown(null);
      return;
    }

    if (visibleDropdown && visibleDropdown !== openDropdown) {
      setLeavingDropdown(visibleDropdown);
      setVisibleDropdown(openDropdown);
      switchTimerRef.current = window.setTimeout(() => {
        setLeavingDropdown(null);
        switchTimerRef.current = null;
      }, CONTENT_SWITCH_MS);
      return;
    }

    if (visibleDropdown !== openDropdown) {
      setVisibleDropdown(openDropdown);
    }
    setLeavingDropdown(null);
  }, [openDropdown, visibleDropdown, clearContentSwitchTimer]);

  React.useEffect(() => {
    if (!openDropdown) return;

    const onResize = () => {
      updateDropdownNotchPosition(openDropdown);
    };

    onResize();
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
    };
  }, [openDropdown, updateDropdownNotchPosition]);

  const getNavLinkProps = React.useCallback(
    (to: string) => {
      const props = linkProps(to);
      return {
        href: props.href,
        onClick: (e: React.MouseEvent<HTMLAnchorElement>) => {
          props.onClick(e);
          closeMenus();
        },
      };
    },
    [linkProps, closeMenus],
  );

  const openDropdownFromKeyboard = React.useCallback(
    (id: DropdownId, focusTarget: DropdownFocusTarget = 'first') => {
      clearDropdownTimers();
      clearContentSwitchTimer();
      setOpenDropdown(id);
      updateDropdownNotchPosition(id);

      requestAnimationFrame(() => {
        const menuItems = getMenuItems(dropdownPanelRef.current, id);
        if (!menuItems.length) return;

        if (focusTarget === 'last') {
          menuItems[menuItems.length - 1]?.focus();
          return;
        }
        menuItems[0]?.focus();
      });
    },
    [clearDropdownTimers, clearContentSwitchTimer, updateDropdownNotchPosition],
  );

  const onDropdownButtonKeyDown = React.useCallback(
    (e: React.KeyboardEvent<HTMLButtonElement>, id: DropdownId) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        closeMenus();
        return;
      }

      if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openDropdownFromKeyboard(id, 'first');
      }

      if (e.key === 'ArrowUp') {
        e.preventDefault();
        openDropdownFromKeyboard(id, 'last');
      }
    },
    [closeMenus, openDropdownFromKeyboard],
  );

  const onDropdownPanelKeyDown = React.useCallback(
    (e: React.KeyboardEvent<HTMLDivElement>) => {
      const id = visibleDropdown ?? openDropdown;
      const menuItems = getMenuItems(dropdownPanelRef.current, id);
      if (!menuItems.length) return;

      const activeIndex = menuItems.findIndex((item) => item === document.activeElement);

      if (e.key === 'Escape') {
        e.preventDefault();
        closeMenus();
        if (id) {
          dropdownButtonRefs.current[id]?.focus();
        }
        return;
      }

      if (e.key === 'Home') {
        e.preventDefault();
        menuItems[0]?.focus();
        return;
      }

      if (e.key === 'End') {
        e.preventDefault();
        menuItems[menuItems.length - 1]?.focus();
        return;
      }

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        const nextIndex = activeIndex < 0 ? 0 : (activeIndex + 1) % menuItems.length;
        menuItems[nextIndex]?.focus();
        return;
      }

      if (e.key === 'ArrowUp') {
        e.preventDefault();
        const nextIndex = activeIndex <= 0 ? menuItems.length - 1 : activeIndex - 1;
        menuItems[nextIndex]?.focus();
      }
    },
    [closeMenus, openDropdown, visibleDropdown],
  );

  React.useEffect(() => {
    if (!openDropdown && !isMobileMenuOpen) return;

    const onPointerDown = (e: PointerEvent) => {
      if (isClickInsideRoot(e.target, rootRef.current)) return;
      closeMenus();
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      closeMenus();
    };

    window.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [closeMenus, isMobileMenuOpen, openDropdown]);

  React.useEffect(() => {
    if (!isDashboardAuthOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      setIsDashboardAuthOpen(false);
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [isDashboardAuthOpen]);

  const docsProps = getNavLinkProps('/docs/getting-started/overview');
  const homeProps = getNavLinkProps('/');
  const aboutRootProps = getNavLinkProps('/company/');
  const pricingProps = getNavLinkProps('/pricing/');
  const contactSalesProps = getNavLinkProps('/contact/');
  const getStartedProps = getNavLinkProps('/dashboard');
  const dashboardEntryAuthenticated = relaySessionAuthenticated;

  const openDashboardAuthModal = React.useCallback(() => {
    closeMenus();
    setDashboardAuthError('');
    setIsDashboardAuthOpen(true);
    void refreshRelaySessionState();
    if (!googleConfigChecked) {
      void refreshGoogleConfigured();
    }
  }, [closeMenus, googleConfigChecked, refreshGoogleConfigured, refreshRelaySessionState]);

  const continueToDashboard = React.useCallback(() => {
    setDashboardAuthError('');
    setIsDashboardAuthOpen(false);
    go('/dashboard');
  }, [go]);

  const onGoogleSignIn = React.useCallback(async () => {
    if (googleSigningIn) return;
    setDashboardAuthError('');
    setGoogleSigningIn(true);
    try {
      if (!googleClientId) {
        throw new Error('Google client ID is not configured on the relay server');
      }
      const configured = googleConfigChecked ? googleConfigured : await refreshGoogleConfigured();
      if (!configured) {
        throw new Error('Google OIDC is not configured on the relay server');
      }
      if (!relayerBaseUrl) {
        throw new Error('Relayer base URL is not configured');
      }

      await ensureGoogleIdentityScriptLoaded();
      const idToken = await requestGoogleIdToken(googleClientId);

      const response = await fetch(`${relayerBaseUrl}/session/exchange`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          session_kind: 'cookie',
          exchange: {
            type: 'oidc_jwt',
            provider: 'google',
            token: idToken,
          },
        }),
      });
      const body = await parseOptionalJson(response);
      if (!response.ok || body?.ok !== true) {
        const message = String(body?.message || '').trim();
        throw new Error(message || `Google session exchange failed (${response.status})`);
      }
      const authenticated = await refreshRelaySessionState();
      if (!authenticated) {
        throw new Error('Google session was issued but could not be validated');
      }
      continueToDashboard();
    } catch (error: unknown) {
      setDashboardAuthError(error instanceof Error ? error.message : String(error));
    } finally {
      setGoogleSigningIn(false);
    }
  }, [
    continueToDashboard,
    googleClientId,
    googleConfigChecked,
    googleConfigured,
    googleSigningIn,
    refreshGoogleConfigured,
    refreshRelaySessionState,
    relayerBaseUrl,
  ]);

  const openDashboardEntry = React.useCallback(() => {
    if (dashboardEntryAuthenticated) {
      go('/dashboard');
      return;
    }
    openDashboardAuthModal();
  }, [dashboardEntryAuthenticated, go, openDashboardAuthModal]);

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const onOpenRequest = () => {
      openDashboardEntry();
    };
    window.addEventListener(DASHBOARD_AUTH_OPEN_EVENT, onOpenRequest as EventListener);
    return () => {
      window.removeEventListener(DASHBOARD_AUTH_OPEN_EVENT, onOpenRequest as EventListener);
    };
  }, [openDashboardEntry]);

  const onDashboardClick = React.useCallback(
    (event: React.MouseEvent<HTMLAnchorElement>) => {
      const modified =
        event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0;
      if (modified) return;
      event.preventDefault();
      openDashboardEntry();
    },
    [openDashboardEntry],
  );

  const dropdownAriaConfig =
    dropdownConfigs.find((config) => config.id === (visibleDropdown ?? openDropdown)) ?? null;
  const activeDropdownId = visibleDropdown ?? openDropdown;
  const dropdownMaxWidthPx = React.useMemo(
    () => getDropdownMaxWidthPx(activeDropdownId),
    [activeDropdownId],
  );
  const dropdownSurfaceStyle = React.useMemo(() => {
    return {
      left: `${dropdownSurfaceLeft}px`,
      '--navbar-dropdown-max-width': `${dropdownMaxWidthPx}px`,
      '--navbar-dropdown-notch-left': `${dropdownNotchLeft}px`,
    } as React.CSSProperties;
  }, [dropdownMaxWidthPx, dropdownNotchLeft, dropdownSurfaceLeft]);

  function renderDropdownTrigger(config: DropdownConfig): React.JSX.Element {
    const isOpen = openDropdown === config.id;

    return (
      <div
        key={config.id}
        className="navbar-static__group"
        onMouseEnter={() => scheduleOpenDropdown(config.id)}
        onMouseLeave={() => scheduleCloseDropdown()}
        onFocusCapture={() => scheduleOpenDropdown(config.id, 0)}
        onBlurCapture={(e) => {
          const next = e.relatedTarget;
          if (next instanceof Node && rootRef.current?.contains(next)) return;
          scheduleCloseDropdown(0);
        }}
      >
        <button
          type="button"
          ref={(el) => {
            dropdownButtonRefs.current[config.id] = el;
          }}
          className={`navbar-static__link navbar-static__link--button${isOpen ? ' is-active' : ''}`}
          aria-expanded={isOpen}
          aria-haspopup="menu"
          aria-controls={`navbar-dropdown-${config.id}`}
          onClick={() => {
            clearDropdownTimers();
            clearContentSwitchTimer();
            setOpenDropdown((open) => {
              if (open === config.id) return null;
              updateDropdownNotchPosition(config.id);
              return config.id;
            });
          }}
          onKeyDown={(e) => onDropdownButtonKeyDown(e, config.id)}
        >
          <span>{config.label}</span>
          <ChevronDown
            size={16}
            className={`navbar-static__chevron${isOpen ? ' is-open' : ''}`}
            aria-hidden
          />
        </button>
      </div>
    );
  }

  return (
    <nav ref={rootRef} className="navbar-static" aria-label="Primary">
      <div ref={shellRef} className={`navbar-static__shell${hasScrolled ? ' is-scrolled' : ''}`}>
        <div className="navbar-static__left">
          <a
            className="navbar-static__brand"
            href={homeProps.href}
            onClick={homeProps.onClick}
            aria-label="Seams home"
          >
            <SeamsLogo size={24} strokeWidth={1.2} />
            <span>Seams</span>
          </a>
        </div>

        <div className="navbar-static__center">
          <div className="navbar-static__links">
            {primaryDropdownConfigs.map(renderDropdownTrigger)}
            <a
              className="navbar-static__link"
              href={docsProps.href}
              onClick={docsProps.onClick}
              target="_blank"
              rel="noopener noreferrer"
            >
              Documentation
            </a>
            <a
              className="navbar-static__link"
              href={pricingProps.href}
              onClick={pricingProps.onClick}
            >
              Pricing
            </a>
            {renderDropdownTrigger(aboutDropdownConfig)}
          </div>
        </div>

        <div className="navbar-static__right">
          <div className="navbar-static__actions">
            <a
              className="navbar-static__pill navbar-static__pill--solid"
              href={getStartedProps.href}
              onClick={onDashboardClick}
            >
              <span>Dashboard</span>
              <ArrowRightAnim size={14} />
            </a>
            <a
              className="navbar-static__pill navbar-static__pill--ghost"
              href={contactSalesProps.href}
              onClick={contactSalesProps.onClick}
            >
              <span>Contact Sales</span>
              <ArrowRightAnim size={14} />
            </a>
            <button
              type="button"
              className="navbar-static__theme-toggle"
              onClick={onToggleTheme}
              aria-label="Toggle dark mode"
              title="Toggle dark mode"
            >
              {resolvedTheme === 'dark' ? (
                <SunIcon size={18} strokeWidth={2} aria-hidden />
              ) : (
                <MoonIcon size={18} strokeWidth={2} aria-hidden />
              )}
            </button>
            <button
              type="button"
              className="navbar-static__mobile-toggle"
              aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
              onClick={() => setIsMobileMenuOpen((open) => !open)}
            >
              {isMobileMenuOpen ? <X size={20} aria-hidden /> : <Menu size={20} aria-hidden />}
            </button>
          </div>
        </div>

        <div
          className={`navbar-static__dropdown-surface${openDropdown ? ' is-open' : ''}`}
          style={dropdownSurfaceStyle}
          onMouseEnter={clearDropdownTimers}
          onMouseLeave={() => scheduleCloseDropdown()}
          onFocusCapture={clearDropdownTimers}
          onBlurCapture={(e) => {
            const next = e.relatedTarget;
            if (next instanceof Node && rootRef.current?.contains(next)) return;
            scheduleCloseDropdown(0);
          }}
        >
          <div
            ref={dropdownPanelRef}
            className="navbar-static__dropdown-inner"
            role="menu"
            aria-label={dropdownAriaConfig ? dropdownAriaConfig.label : undefined}
            aria-orientation="vertical"
            onKeyDown={onDropdownPanelKeyDown}
          >
            <div className="navbar-static__dropdown-stack">
              {dropdownConfigs.map((config) => {
                const rootProps = config.rootTo ? getNavLinkProps(config.rootTo) : null;
                const isActive = activeDropdownId === config.id && leavingDropdown !== config.id;
                const isLeaving = leavingDropdown === config.id;
                const viewClassName = [
                  'navbar-static__dropdown-view',
                  isActive ? 'is-active' : '',
                  isLeaving ? 'is-leaving' : '',
                ]
                  .filter(Boolean)
                  .join(' ');

                return (
                  <div
                    key={config.id}
                    id={`navbar-dropdown-${config.id}`}
                    className={viewClassName}
                    data-dropdown-view={config.id}
                    aria-hidden={!isActive}
                  >
                    {config.sections.map((section) => (
                      <section className="navbar-static__dropdown-section" key={section.heading}>
                        <h3 className="navbar-static__dropdown-title">{section.heading}</h3>
                        <div className="navbar-static__dropdown-grid">
                          {section.items.map((item) => {
                            const itemProps = getNavLinkProps(item.to);
                            return (
                              <a
                                key={item.title}
                                className="navbar-static__dropdown-card"
                                role="menuitem"
                                href={itemProps.href}
                                onClick={itemProps.onClick}
                              >
                                <p className="navbar-static__dropdown-card-title">{item.title}</p>
                                <p className="navbar-static__dropdown-card-description">
                                  {item.description}
                                </p>
                              </a>
                            );
                          })}
                        </div>
                      </section>
                    ))}
                    {config.allLabel && rootProps ? (
                      <a
                        className="navbar-static__dropdown-all"
                        role="menuitem"
                        href={rootProps.href}
                        onClick={rootProps.onClick}
                      >
                        {config.allLabel}
                      </a>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {isDashboardAuthOpen ? (
        <div
          className="navbar-static__auth-overlay"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target !== event.currentTarget) return;
            setIsDashboardAuthOpen(false);
          }}
        >
          <DashboardGoogleAuthCard
            classNames={{
              root: 'navbar-static__auth-modal',
              header: 'navbar-static__auth-header',
              heading: 'navbar-static__auth-heading',
              eyebrow: 'navbar-static__auth-eyebrow',
              copy: 'navbar-static__auth-copy',
              provider: 'navbar-static__auth-provider',
              providerIcon: 'navbar-static__auth-provider-icon',
              providerBody: 'navbar-static__auth-provider-body',
              providerLabel: 'navbar-static__auth-provider-label',
              providerCopy: 'navbar-static__auth-provider-copy',
              ctaButton: 'navbar-static__auth-google-button',
              ctaIcon: 'navbar-static__auth-google-button-icon',
              note: 'navbar-static__auth-note',
              error: 'navbar-static__auth-error',
            }}
            rootAttributes={{
              role: 'dialog',
              'aria-modal': true,
              'aria-labelledby': 'navbar-dashboard-auth-title',
              onMouseDown: (event) => event.stopPropagation(),
            }}
            titleId="navbar-dashboard-auth-title"
            title="Sign In To Open Dashboard"
            description="Use Google SSO to enter the console. Wallet passkeys can be added later inside the dashboard when you create wallets for stablecoin billing."
            providerLabel="Google SSO"
            providerDescription="One secure sign-in to open the dashboard and start managing billing."
            continueLabel={
              googleSigningIn
                ? 'Signing in with Google...'
                : !googleClientId
                  ? 'Google SSO unavailable'
                  : !googleConfigChecked
                    ? 'Checking Google SSO...'
                    : !googleConfigured
                      ? 'Google SSO not configured'
                      : 'Continue with Google'
            }
            continueDisabled={googleSigningIn || relaySessionLoading || !googleConfigured}
            onContinue={() => {
              void onGoogleSignIn();
            }}
            note={
              googleConfigChecked && googleConfigured
                ? 'Google signs you into the dashboard first. Wallet passkeys are created later inside the console.'
                : 'Set GOOGLE_OIDC_CLIENT_ID or GOOGLE_OIDC_CLIENT_IDS on the relay to enable dashboard sign-in.'
            }
            errorMessage={dashboardAuthError}
            closeControl={
              <button
                type="button"
                className="navbar-static__auth-close"
                onClick={() => setIsDashboardAuthOpen(false)}
                aria-label="Close dashboard sign-in"
              >
                <X size={18} aria-hidden />
              </button>
            }
          />
        </div>
      ) : null}

      <div className={`navbar-static__mobile-menu${isMobileMenuOpen ? ' is-open' : ''}`}>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobileProductsOpen}
          onClick={() => {
            setIsMobileProductsOpen((open) => !open);
            setIsMobileSolutionsOpen(false);
            setIsMobileAboutOpen(false);
          }}
        >
          <span>Products</span>
          <ChevronDown
            size={16}
            className={`navbar-static__chevron${isMobileProductsOpen ? ' is-open' : ''}`}
            aria-hidden
          />
        </button>
        <div className={`navbar-static__mobile-submenu${isMobileProductsOpen ? ' is-open' : ''}`}>
          {productSections.map((section) => (
            <section key={section.heading} className="navbar-static__mobile-section">
              <h3 className="navbar-static__mobile-section-title">{section.heading}</h3>
              {section.items.map((item) => {
                const itemProps = getNavLinkProps(item.to);
                return (
                  <a
                    key={item.title}
                    className="navbar-static__mobile-subitem"
                    href={itemProps.href}
                    onClick={itemProps.onClick}
                  >
                    <span>{item.title}</span>
                    <small>{item.description}</small>
                  </a>
                );
              })}
            </section>
          ))}
        </div>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobileSolutionsOpen}
          onClick={() => {
            setIsMobileSolutionsOpen((open) => !open);
            setIsMobileProductsOpen(false);
            setIsMobileAboutOpen(false);
          }}
        >
          <span>Solutions</span>
          <ChevronDown
            size={16}
            className={`navbar-static__chevron${isMobileSolutionsOpen ? ' is-open' : ''}`}
            aria-hidden
          />
        </button>
        <div className={`navbar-static__mobile-submenu${isMobileSolutionsOpen ? ' is-open' : ''}`}>
          {solutionSections.map((section) => (
            <section key={section.heading} className="navbar-static__mobile-section">
              <h3 className="navbar-static__mobile-section-title">{section.heading}</h3>
              {section.items.map((item) => {
                const itemProps = getNavLinkProps(item.to);
                return (
                  <a
                    key={item.title}
                    className="navbar-static__mobile-subitem"
                    href={itemProps.href}
                    onClick={itemProps.onClick}
                  >
                    <span>{item.title}</span>
                    <small>{item.description}</small>
                  </a>
                );
              })}
            </section>
          ))}
        </div>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobileAboutOpen}
          onClick={() => {
            setIsMobileAboutOpen((open) => !open);
            setIsMobileProductsOpen(false);
            setIsMobileSolutionsOpen(false);
          }}
        >
          <span>About Us</span>
          <ChevronDown
            size={16}
            className={`navbar-static__chevron${isMobileAboutOpen ? ' is-open' : ''}`}
            aria-hidden
          />
        </button>
        <div className={`navbar-static__mobile-submenu${isMobileAboutOpen ? ' is-open' : ''}`}>
          {aboutSections.map((section) => (
            <section key={section.heading} className="navbar-static__mobile-section">
              <h3 className="navbar-static__mobile-section-title">{section.heading}</h3>
              {section.items.map((item) => {
                const itemProps = getNavLinkProps(item.to);
                return (
                  <a
                    key={item.title}
                    className="navbar-static__mobile-subitem"
                    href={itemProps.href}
                    onClick={itemProps.onClick}
                  >
                    <span>{item.title}</span>
                    <small>{item.description}</small>
                  </a>
                );
              })}
            </section>
          ))}
          <a
            className="navbar-static__mobile-subitem"
            href={aboutRootProps.href}
            onClick={aboutRootProps.onClick}
          >
            <span>View company overview</span>
            <small>Learn more about the Seams team and mission</small>
          </a>
        </div>
        <a
          className="navbar-static__mobile-link"
          href={docsProps.href}
          onClick={docsProps.onClick}
          target="_blank"
          rel="noopener noreferrer"
        >
          Documentation
        </a>
        <a
          className="navbar-static__mobile-link"
          href={pricingProps.href}
          onClick={pricingProps.onClick}
        >
          Pricing
        </a>
        <div className="navbar-static__mobile-cta-row">
          <a
            className="navbar-static__pill navbar-static__pill--solid"
            href={getStartedProps.href}
            onClick={onDashboardClick}
          >
            <span>Dashboard</span>
            <ArrowRightAnim size={14} />
          </a>
          <a
            className="navbar-static__pill navbar-static__pill--ghost"
            href={contactSalesProps.href}
            onClick={contactSalesProps.onClick}
          >
            <span>Contact Sales</span>
            <ArrowRightAnim size={14} />
          </a>
        </div>
      </div>
    </nav>
  );
}

export default NavbarStatic;
