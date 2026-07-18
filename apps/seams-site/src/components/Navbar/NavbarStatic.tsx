import React from 'react';
import {
  BookOpen,
  Bot,
  Building2,
  ChevronDown,
  Fingerprint,
  LifeBuoy,
  ListChecks,
  Menu,
  PenLine,
  Rocket,
  Sprout,
  TrendingUp,
  Wallet,
  Wrench,
  X,
} from 'lucide-react';
import { ArrowRightAnim } from '../ArrowRightAnim';
import SeamsWordmark from '../icons/SeamsWordmark';
import { DashboardGoogleAuthCard } from '@/shared/auth/DashboardGoogleAuthCard';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { FRONTEND_CONFIG } from '@/config';
import {
  ensureGoogleIdentityScriptLoaded,
  fetchGoogleAuthOptions,
  requestGoogleIdToken,
} from '@/shared/auth/googleIdentity';
import './Navbar.css';

type DropdownId = 'products' | 'documentation' | 'about' | 'pricing';

type MenuRow = {
  title: string;
  description: string;
  to: string;
  icon: React.ComponentType<{ size?: number; strokeWidth?: number; 'aria-hidden'?: boolean }>;
  /** Small right-aligned annotation, e.g. a plan's price basis. */
  meta?: string;
};

/** Which gradient asset backs the pane's highlight card (see Navbar.css). */
type MenuHighlightTone = 'aqua' | 'bluegreen' | 'ember';

type MenuHighlight = {
  title: string;
  description: string;
  to: string;
  tone: MenuHighlightTone;
};

type MenuFooterLink = {
  label: string;
  to: string;
};

type DropdownPane = {
  id: DropdownId;
  label: string;
  kicker: string;
  rows: MenuRow[];
  /** Optional gradient promo card on the pane's right side. */
  highlight?: MenuHighlight;
  footerLinks: MenuFooterLink[];
};

type DropdownTriggerConfig = {
  id: DropdownId;
  label: string;
};

type DropdownFocusTarget = 'first' | 'last';
const DASHBOARD_AUTH_OPEN_EVENT = 'seams:dashboard-auth-open';

/* The 'documentation' pane id historically maps to the "Products" trigger and
   vice versa; ids are kept stable so aria wiring and pane ordering don't churn. */
const documentationDropdownPane: DropdownPane = {
  id: 'documentation',
  label: 'Products',
  kicker: 'Products',
  rows: [
    {
      title: 'Embedded Wallet',
      description: 'Non-custodial wallets with policy-bound keys and sessions',
      to: '/wallet',
      icon: Wallet,
    },
    {
      title: 'Ecommerce Agents',
      description: 'AI agents with scoped credentials, acting inside policy',
      to: '/ecommerce',
      icon: Bot,
    },
    {
      title: 'Biometric Authentication',
      description: 'Passkey and VoiceID flows for owner presence',
      to: '/docs/concepts/auth-methods/passkeys',
      icon: Fingerprint,
    },
  ],
  highlight: {
    title: 'Live demo',
    description: 'Create a passkey wallet on the Embedded Wallet page',
    to: '/wallet',
    tone: 'aqua',
  },
  footerLinks: [{ label: 'Plan pricing', to: '/pricing/' }],
};

const productsDropdownPane: DropdownPane = {
  id: 'products',
  label: 'Documentation',
  kicker: 'Documentation',
  rows: [
    {
      title: 'Guides',
      description: 'Key, credential, policy, and signing architecture',
      to: '/docs/concepts/',
      icon: BookOpen,
    },
    {
      title: 'Tools',
      description: 'SDK references for auth, sessions, wallet UI, and policy',
      to: '/docs/concepts/auth-methods/',
      icon: Wrench,
    },
    {
      title: 'Use cases',
      description: 'Mandates, payments, recovery, and delegated agents',
      to: '/docs/concepts/policy/mandates',
      icon: ListChecks,
    },
  ],
  highlight: {
    title: 'Architecture',
    description: 'How passkeys, policy, and signing fit together',
    to: '/docs/concepts/architecture',
    tone: 'bluegreen',
  },
  footerLinks: [{ label: 'Read the docs', to: '/docs/concepts/' }],
};

const pricingDropdownPane: DropdownPane = {
  id: 'pricing',
  label: 'Pricing',
  kicker: 'Plans',
  rows: [
    {
      title: 'Starter',
      description: 'Up to 5K monthly active wallets',
      to: '/pricing/#starter',
      icon: Sprout,
      meta: 'Included',
    },
    {
      title: 'Growth',
      description: '5K–100K monthly active wallets',
      to: '/pricing/#growth',
      icon: TrendingUp,
      meta: 'Usage-based',
    },
    {
      title: 'Scale',
      description: '100K+ monthly active wallets, SLA, and advanced controls',
      to: '/pricing/#scale',
      icon: Rocket,
      meta: 'Volume',
    },
  ],
  footerLinks: [
    { label: 'Compare plans', to: '/pricing/' },
    { label: 'Contact sales', to: '/contact/' },
  ],
};

const aboutDropdownPane: DropdownPane = {
  id: 'about',
  label: 'About Us',
  kicker: 'Company',
  rows: [
    {
      title: 'Company',
      description: 'Who we are and what we are building',
      to: '/company/',
      icon: Building2,
    },
    {
      title: 'Blog',
      description: 'Writing from the Seams team',
      to: '/company/#blog',
      icon: PenLine,
    },
    {
      title: 'Support',
      description: 'Get help from the team',
      to: '/contact/',
      icon: LifeBuoy,
    },
  ],
  highlight: {
    title: 'Plan a rollout',
    description: 'Talk through marketplaces and merchant fleets',
    to: '/contact/',
    tone: 'ember',
  },
  footerLinks: [{ label: 'Contact sales', to: '/contact/' }],
};

const dropdownPanes: DropdownPane[] = [
  productsDropdownPane,
  documentationDropdownPane,
  aboutDropdownPane,
  pricingDropdownPane,
];

/* Visual left-to-right order of the dropdown triggers in the bar; drives which
   side inactive panes park on so a menu switch slides content in from the
   direction of travel (restores the pre-refresh pane slide). */
const DROPDOWN_VISUAL_ORDER: DropdownId[] = ['documentation', 'products', 'pricing', 'about'];

function paneOrderIndex(id: DropdownId): number {
  return DROPDOWN_VISUAL_ORDER.indexOf(id);
}

function paneVisualClass(paneId: DropdownId, activeId: DropdownId | null): string {
  if (paneId === activeId) return 'is-active';
  if (!activeId) return 'is-after';
  return paneOrderIndex(paneId) < paneOrderIndex(activeId) ? 'is-before' : 'is-after';
}

const primaryDropdownTriggers: DropdownTriggerConfig[] = [
  {
    id: 'documentation',
    label: 'Products',
  },
  {
    id: 'products',
    label: 'Documentation',
  },
];

const aboutDropdownTrigger: DropdownTriggerConfig = {
  id: 'about',
  label: 'About Us',
};

const pricingDropdownTrigger: DropdownTriggerConfig = {
  id: 'pricing',
  label: 'Pricing',
};

function isClickInsideRoot(target: EventTarget | null, root: HTMLElement | null): boolean {
  return !!(target instanceof Node && root && root.contains(target));
}

function getMenuItems(panel: HTMLDivElement | null, id: DropdownId | null): HTMLElement[] {
  if (!panel || !id) return [];
  return Array.from(
    panel.querySelectorAll<HTMLElement>(`[data-dropdown-view="${id}"] a[role="menuitem"]`),
  );
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

export type NavbarStaticProps = {
  /** 'auto' follows the site theme; 'light' pins the light-page skin (used by /home2). */
  appearance?: 'auto' | 'light';
};

export function NavbarStatic({ appearance = 'auto' }: NavbarStaticProps = {}): React.JSX.Element {
  const OPEN_DELAY_MS = 0;
  const CLOSE_DELAY_MS = 120;
  const SCROLL_THRESHOLD_PX = 8;

  const { go, linkProps } = useSiteRouter();
  const relayerBaseUrl = React.useMemo(
    () => normalizeBaseUrl(FRONTEND_CONFIG.relayerUrl || FRONTEND_CONFIG.consoleBaseUrl),
    [],
  );
  const [googleClientId, setGoogleClientId] = React.useState<string>('');
  const rootRef = React.useRef<HTMLElement | null>(null);
  const dropdownButtonRefs = React.useRef<Record<DropdownId, HTMLButtonElement | null>>({
    products: null,
    documentation: null,
    pricing: null,
    about: null,
  });
  const dropdownPanelRef = React.useRef<HTMLDivElement | null>(null);
  const dropdownPopupRef = React.useRef<HTMLDivElement | null>(null);
  const paneRefs = React.useRef<Record<DropdownId, HTMLDivElement | null>>({
    products: null,
    documentation: null,
    pricing: null,
    about: null,
  });
  const prevOpenDropdownRef = React.useRef<DropdownId | null>(null);
  const openTimerRef = React.useRef<number | null>(null);
  const closeTimerRef = React.useRef<number | null>(null);
  const [openDropdown, setOpenDropdown] = React.useState<DropdownId | null>(null);
  const [paneSize, setPaneSize] = React.useState<{ w: number; h: number } | null>(null);
  // Horizontal anchor: the popup centers on the trigger that opened it,
  // clamped so the panel never overhangs the bar.
  const [popupLeft, setPopupLeft] = React.useState<number | null>(null);
  // The card morphs between pane sizes only while already open; opening from
  // closed snaps to size so the panel doesn't grow out of the previous shape.
  const [paneMorphEnabled, setPaneMorphEnabled] = React.useState<boolean>(false);
  const [hasScrolled, setHasScrolled] = React.useState<boolean>(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState<boolean>(false);
  const [isMobileProductsOpen, setIsMobileProductsOpen] = React.useState<boolean>(false);
  const [isMobileDocumentationOpen, setIsMobileDocumentationOpen] = React.useState<boolean>(false);
  const [isMobilePricingOpen, setIsMobilePricingOpen] = React.useState<boolean>(false);
  const [isMobileAboutOpen, setIsMobileAboutOpen] = React.useState<boolean>(false);
  const [isDashboardAuthOpen, setIsDashboardAuthOpen] = React.useState<boolean>(false);
  const [dashboardAuthError, setDashboardAuthError] = React.useState<string>('');
  const [relaySessionLoading, setRelaySessionLoading] = React.useState<boolean>(false);
  const [relaySessionAuthenticated, setRelaySessionAuthenticated] = React.useState<boolean>(false);
  const [googleConfigChecked, setGoogleConfigChecked] = React.useState<boolean>(false);
  const [googleConfigured, setGoogleConfigured] = React.useState<boolean>(false);
  const [googleSigningIn, setGoogleSigningIn] = React.useState<boolean>(false);

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

  // Measure the active pane (panes are absolutely positioned at max-content,
  // so offset sizes are their natural dimensions even while hidden) and morph
  // the card chrome to it — the ElevenLabs-style resize between menus. The
  // popup's left edge stays pinned to the first nav trigger for every pane,
  // so switching menus only resizes the panel; it never slides around.
  React.useLayoutEffect(() => {
    const previousOpen = prevOpenDropdownRef.current;
    prevOpenDropdownRef.current = openDropdown;
    // Keep the last size/anchor while closing so the panel fades out in place.
    if (!openDropdown) {
      setPaneMorphEnabled(false);
      return;
    }
    const pane = paneRefs.current[openDropdown];
    if (!pane) return;
    const paneW = pane.offsetWidth;
    const paneH = pane.offsetHeight;
    const shell = dropdownPopupRef.current?.offsetParent as HTMLElement | null;
    const firstTrigger = shell?.querySelector<HTMLElement>(
      '.navbar-static__links .navbar-static__link--button',
    );
    if (shell && firstTrigger) {
      const shellRect = shell.getBoundingClientRect();
      // an ancestor's css zoom scales rect coordinates but not offset/style
      // px; normalize rect-derived values back to layout px
      const zoom = shell.offsetWidth ? shellRect.width / shell.offsetWidth : 1;
      const anchor = (firstTrigger.getBoundingClientRect().left - shellRect.left) / zoom;
      // Only yield the anchor if a wide panel would overhang the bar's right edge.
      setPopupLeft(Math.max(8, Math.min(anchor, shellRect.width / zoom - paneW - 8)));
    }
    setPaneMorphEnabled(previousOpen !== null && previousOpen !== openDropdown);
    setPaneSize({ w: paneW, h: paneH });
  }, [openDropdown]);

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
        openTimerRef.current = null;
      }, effectiveDelayMs);
    },
    [isMobileMenuOpen, openDropdown],
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
    setOpenDropdown(null);
    setIsMobileMenuOpen(false);
    setIsMobileProductsOpen(false);
    setIsMobileDocumentationOpen(false);
    setIsMobilePricingOpen(false);
    setIsMobileAboutOpen(false);
  }, [clearDropdownTimers]);

  React.useEffect(() => {
    return () => {
      clearDropdownTimers();
    };
  }, [clearDropdownTimers]);

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
      setOpenDropdown(id);

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
    [clearDropdownTimers],
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
      const id = openDropdown;
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
    [closeMenus, openDropdown],
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

  const homeProps = getNavLinkProps('/');
  const aboutRootProps = getNavLinkProps('/company/');
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
        throw new Error('Google client ID is not configured on the Router API server');
      }
      const configured = googleConfigChecked ? googleConfigured : await refreshGoogleConfigured();
      if (!configured) {
        throw new Error('Google OIDC is not configured on the Router API server');
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

  const dropdownAriaConfig = dropdownPanes.find((config) => config.id === openDropdown) ?? null;

  function renderDropdownTrigger(config: DropdownTriggerConfig): React.JSX.Element {
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
            setOpenDropdown((open) => {
              if (open === config.id) return null;
              return config.id;
            });
          }}
          onKeyDown={(e) => onDropdownButtonKeyDown(e, config.id)}
        >
          <span>{config.label}</span>
        </button>
      </div>
    );
  }

  function renderAccessPane(pane: DropdownPane): React.JSX.Element {
    const isActive = pane.id === openDropdown;
    const paneClassName = `navbar-static__access-pane ${paneVisualClass(pane.id, openDropdown)}`;

    const highlightProps = pane.highlight ? getNavLinkProps(pane.highlight.to) : null;

    return (
      <div
        key={pane.id}
        id={`navbar-dropdown-${pane.id}`}
        ref={(el) => {
          paneRefs.current[pane.id] = el;
        }}
        className={paneClassName}
        data-dropdown-view={pane.id}
        aria-hidden={!isActive}
      >
        <div className="navbar-static__menu">
          <div className="navbar-static__menu-body">
            <div className="navbar-static__menu-col">
              <p className="navbar-static__menu-kicker">{pane.kicker}</p>
              {pane.rows.map((row) => {
                const rowProps = getNavLinkProps(row.to);
                const Icon = row.icon;
                return (
                  <a
                    key={row.title}
                    className="navbar-static__menu-row"
                    role="menuitem"
                    href={rowProps.href}
                    onClick={rowProps.onClick}
                    tabIndex={isActive ? undefined : -1}
                  >
                    <span className="navbar-static__menu-row-icon" aria-hidden>
                      <Icon size={16} strokeWidth={1.7} />
                    </span>
                    <span className="navbar-static__menu-row-text">
                      <span className="navbar-static__menu-row-title">{row.title}</span>
                      <span className="navbar-static__menu-row-description">
                        {row.description}
                      </span>
                    </span>
                    {row.meta ? (
                      <span className="navbar-static__menu-row-meta">{row.meta}</span>
                    ) : null}
                  </a>
                );
              })}
            </div>
            {pane.highlight && highlightProps ? (
              <div className="navbar-static__menu-side">
                <a
                  className={`navbar-static__menu-highlight navbar-static__menu-highlight--${pane.highlight.tone}`}
                  role="menuitem"
                  href={highlightProps.href}
                  onClick={highlightProps.onClick}
                  tabIndex={isActive ? undefined : -1}
                >
                  <span className="navbar-static__menu-highlight-title">
                    {pane.highlight.title}
                  </span>
                  <span className="navbar-static__menu-highlight-description">
                    {pane.highlight.description}
                  </span>
                </a>
              </div>
            ) : null}
          </div>
          <div className="navbar-static__menu-footer">
            {pane.footerLinks.map((link) => {
              const linkNavProps = getNavLinkProps(link.to);
              return (
                <a
                  key={link.label}
                  className="navbar-static__menu-footer-link"
                  role="menuitem"
                  href={linkNavProps.href}
                  onClick={linkNavProps.onClick}
                  tabIndex={isActive ? undefined : -1}
                >
                  <span>{link.label}</span>
                  <ArrowRightAnim size={12} />
                </a>
              );
            })}
          </div>
        </div>
      </div>
    );
  }

  return (
    <nav
      ref={rootRef}
      className={`navbar-static${appearance === 'light' ? ' navbar-static--light' : ''}`}
      aria-label="Primary"
    >
      <div className={`navbar-static__shell${hasScrolled ? ' is-scrolled' : ''}`}>
        <div className="navbar-static__left">
          <a
            className="navbar-static__brand"
            href={homeProps.href}
            onClick={homeProps.onClick}
            aria-label="Seams home"
          >
            <SeamsWordmark
              className="navbar-static__brand-wordmark"
              height={17}
              theme={appearance === 'light' ? 'light' : undefined}
            />
          </a>
        </div>

        <div className="navbar-static__center">
          <div className="navbar-static__links">
            {primaryDropdownTriggers.map(renderDropdownTrigger)}
            {renderDropdownTrigger(pricingDropdownTrigger)}
            {renderDropdownTrigger(aboutDropdownTrigger)}
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
              className="navbar-static__mobile-toggle"
              aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
              onClick={() => setIsMobileMenuOpen((open) => !open)}
            >
              <span
                className="navbar-static__context-icon"
                key={isMobileMenuOpen ? 'close' : 'menu'}
              >
                {isMobileMenuOpen ? <X size={20} aria-hidden /> : <Menu size={20} aria-hidden />}
              </span>
            </button>
          </div>
        </div>

        <div
          ref={dropdownPopupRef}
          className={`navbar-static__access-popup${openDropdown ? ' is-open' : ''}${
            paneMorphEnabled ? ' is-morphing' : ''
          }`}
          style={popupLeft !== null ? { left: popupLeft } : undefined}
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
            className="navbar-static__access-card"
            role="menu"
            aria-label={dropdownAriaConfig ? dropdownAriaConfig.label : undefined}
            aria-orientation="vertical"
            onKeyDown={onDropdownPanelKeyDown}
          >
            <div
              className={`navbar-static__access-grid-shell${
                paneMorphEnabled ? ' is-morphing' : ''
              }`}
              style={paneSize ? { width: paneSize.w, height: paneSize.h } : undefined}
            >
              {dropdownPanes.map(renderAccessPane)}
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
            setIsMobileDocumentationOpen(false);
            setIsMobilePricingOpen(false);
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
          <section className="navbar-static__mobile-section">
            <h3 className="navbar-static__mobile-section-title">Products</h3>
            {documentationDropdownPane.rows.map((row) => {
              const rowProps = getNavLinkProps(row.to);
              return (
                <a
                  key={row.title}
                  className="navbar-static__mobile-subitem"
                  href={rowProps.href}
                  onClick={rowProps.onClick}
                >
                  <span>{row.title}</span>
                  <small>{row.description}</small>
                </a>
              );
            })}
          </section>
        </div>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobileDocumentationOpen}
          onClick={() => {
            setIsMobileDocumentationOpen((open) => !open);
            setIsMobileProductsOpen(false);
            setIsMobilePricingOpen(false);
            setIsMobileAboutOpen(false);
          }}
        >
          <span>Documentation</span>
          <ChevronDown
            size={16}
            className={`navbar-static__chevron${isMobileDocumentationOpen ? ' is-open' : ''}`}
            aria-hidden
          />
        </button>
        <div
          className={`navbar-static__mobile-submenu${isMobileDocumentationOpen ? ' is-open' : ''}`}
        >
          <section className="navbar-static__mobile-section">
            <h3 className="navbar-static__mobile-section-title">Documentation</h3>
            {productsDropdownPane.rows.map((row) => {
              const rowProps = getNavLinkProps(row.to);
              return (
                <a
                  key={row.title}
                  className="navbar-static__mobile-subitem"
                  href={rowProps.href}
                  onClick={rowProps.onClick}
                >
                  <span>{row.title}</span>
                  <small>{row.description}</small>
                </a>
              );
            })}
          </section>
        </div>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobileAboutOpen}
          onClick={() => {
            setIsMobileAboutOpen((open) => !open);
            setIsMobileProductsOpen(false);
            setIsMobileDocumentationOpen(false);
            setIsMobilePricingOpen(false);
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
          <section className="navbar-static__mobile-section">
            <h3 className="navbar-static__mobile-section-title">Company</h3>
            {aboutDropdownPane.rows.map((row) => {
              const rowProps = getNavLinkProps(row.to);
              return (
                <a
                  key={row.title}
                  className="navbar-static__mobile-subitem"
                  href={rowProps.href}
                  onClick={rowProps.onClick}
                >
                  <span>{row.title}</span>
                  <small>{row.description}</small>
                </a>
              );
            })}
          </section>
          <a
            className="navbar-static__mobile-subitem"
            href={aboutRootProps.href}
            onClick={aboutRootProps.onClick}
          >
            <span>View company overview</span>
            <small>Learn more about the Seams team and mission</small>
          </a>
        </div>
        <button
          type="button"
          className="navbar-static__mobile-link navbar-static__mobile-link--button"
          aria-expanded={isMobilePricingOpen}
          onClick={() => {
            setIsMobilePricingOpen((open) => !open);
            setIsMobileProductsOpen(false);
            setIsMobileDocumentationOpen(false);
            setIsMobileAboutOpen(false);
          }}
        >
          <span>Pricing</span>
          <ChevronDown
            size={16}
            className={`navbar-static__chevron${isMobilePricingOpen ? ' is-open' : ''}`}
            aria-hidden
          />
        </button>
        <div className={`navbar-static__mobile-submenu${isMobilePricingOpen ? ' is-open' : ''}`}>
          <section className="navbar-static__mobile-section">
            <h3 className="navbar-static__mobile-section-title">Plans</h3>
            {pricingDropdownPane.rows.map((row) => {
              const rowProps = getNavLinkProps(row.to);
              return (
                <a
                  key={row.title}
                  className="navbar-static__mobile-subitem"
                  href={rowProps.href}
                  onClick={rowProps.onClick}
                >
                  <span>{row.title}</span>
                  <small>{row.description}</small>
                </a>
              );
            })}
          </section>
          <a
            className="navbar-static__mobile-subitem"
            href={contactSalesProps.href}
            onClick={contactSalesProps.onClick}
          >
            <span>Talk to us</span>
            <small>Plan pricing and deployment options with the Seams team</small>
          </a>
        </div>
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
