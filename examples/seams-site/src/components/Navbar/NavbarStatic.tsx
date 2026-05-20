import React from 'react';
import { BookOpen, ChevronDown, MessageCircle, Menu, X } from 'lucide-react';
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
import menuAccessPassesImage from '@/assets/navbar/menu-access-passes-wire-light.png';
import menuBiometricAuthDarkImage from '@/assets/navbar/menu-biometric-auth-wire-dark.png';
import menuBiometricAuthLightImage from '@/assets/navbar/menu-biometric-auth-wire-light.png';
import menuBlogImage from '@/assets/navbar/menu-blog.png';
import menuCompanyImage from '@/assets/navbar/menu-company.png';
import menuEmbeddedWalletsImage from '@/assets/navbar/menu-embedded-wallets-wire-light.png';
import menuGuidesImage from '@/assets/navbar/menu-guides-wire-light.png';
import menuSupportImage from '@/assets/navbar/menu-support.png';
import menuToolsImage from '@/assets/navbar/menu-tools-wire-light.png';
import menuUseCasesImage from '@/assets/navbar/menu-use-cases-wire-light.png';
import './Navbar.css';

type DropdownId = 'products' | 'documentation' | 'about' | 'pricing';

type DropdownItem = {
  title: string;
  description: string;
  to: string;
  imageSrc: string;
  imageDarkSrc?: string;
};

type DropdownSectionItem =
  | (DropdownItem & { visual: 'image' })
  | {
      title: string;
      description: string;
      to: string;
      visual: 'plan';
      price: string;
      priceNote: string;
      details: string[];
      imageSrc?: never;
      imageDarkSrc?: never;
    };

type DropdownSection = {
  heading: string;
  items: DropdownSectionItem[];
};

type DropdownCtaIcon = 'docs' | 'pricing' | 'contact';

type DropdownCtaTile = {
  icon: DropdownCtaIcon;
  title: string;
  description: string;
  label: string;
  to: string;
};

type ProductDropdownTile = DropdownItem & {
  id: 'guides' | 'tools' | 'use-cases';
};

type DocumentationDropdownTile = DropdownItem & {
  id: 'embedded-wallets' | 'access-passes' | 'biometric-auth';
};

type ProductDropdownPane = {
  id: 'products';
  label: string;
  layout: 'product-tiles';
  tiles: ProductDropdownTile[];
  sections?: never;
  cta: DropdownCtaTile;
};

type DocumentationDropdownPane = {
  id: 'documentation';
  label: string;
  layout: 'pricing-tiles';
  tiles: DocumentationDropdownTile[];
  sections?: never;
  cta: DropdownCtaTile;
};

type SectionDropdownPane = {
  id: 'about' | 'pricing';
  label: string;
  layout: 'sections';
  sections: DropdownSection[];
  tiles?: never;
  cta: DropdownCtaTile;
};

type DropdownPane = ProductDropdownPane | DocumentationDropdownPane | SectionDropdownPane;

type DropdownTriggerConfig = {
  id: DropdownId;
  label: string;
};

type PaneVisualState = { kind: 'active' } | { kind: 'before' } | { kind: 'after' };

type DropdownFocusTarget = 'first' | 'last';
const DASHBOARD_AUTH_OPEN_EVENT = 'seams:dashboard-auth-open';

function assertNever(value: never): never {
  throw new Error(`Unhandled navbar state: ${JSON.stringify(value)}`);
}

const productDropdownTiles: ProductDropdownTile[] = [
  {
    id: 'guides',
    title: 'Guides',
    description: 'Learn, create, and ship embedded wallet flows with focused implementation guides',
    to: '/docs/getting-started/overview',
    imageSrc: menuGuidesImage,
  },
  {
    id: 'tools',
    title: 'Tools',
    description: 'SDK resources for passkeys, signing sessions, and secure wallet UI',
    to: '/docs/getting-started/quickstart',
    imageSrc: menuToolsImage,
  },
  {
    id: 'use-cases',
    title: 'Use cases',
    description: 'Explore wallet, payment, recovery, and policy-controlled signing patterns',
    to: '/docs/concepts/security-model',
    imageSrc: menuUseCasesImage,
  },
];

const documentationDropdownTiles: DocumentationDropdownTile[] = [
  {
    id: 'embedded-wallets',
    title: 'Embedded Wallets',
    description: 'Self-serve wallet infrastructure for apps launching passkey accounts',
    to: '/pricing/',
    imageSrc: menuEmbeddedWalletsImage,
  },
  {
    id: 'access-passes',
    title: 'Access Passes with account recovery',
    description: 'Recoverable user access for teams that need durable account continuity',
    to: '/pricing/',
    imageSrc: menuAccessPassesImage,
  },
  {
    id: 'biometric-auth',
    title: 'Biometric Authentication',
    description: 'Passkey-first authentication packages for higher assurance sign-in',
    to: '/pricing/',
    imageSrc: menuBiometricAuthLightImage,
    imageDarkSrc: menuBiometricAuthDarkImage,
  },
];

const aboutSections: DropdownSection[] = [
  {
    heading: 'Company',
    items: [
      {
        title: 'Company',
        description: 'Company details',
        to: '/company/#careers',
        visual: 'image',
        imageSrc: menuCompanyImage,
      },
    ],
  },
  {
    heading: 'Writing',
    items: [
      {
        title: 'Blog',
        description: 'Read the latest from our team',
        to: '/company/#blog',
        visual: 'image',
        imageSrc: menuBlogImage,
      },
    ],
  },
  {
    heading: 'Support',
    items: [
      {
        title: 'Support',
        description: 'Join our developer Slack community',
        to: '/contact/',
        visual: 'image',
        imageSrc: menuSupportImage,
      },
    ],
  },
];

const pricingSections: DropdownSection[] = [
  {
    heading: 'Starter',
    items: [
      {
        title: 'Starter',
        description:
          'Build and launch fast for teams shipping embedded wallets for the first time.',
        to: '/pricing/#starter',
        visual: 'plan',
        price: 'Included',
        priceNote: 'Up to 5K MAW',
        details: [
          'Passkey login and embedded wallet SDK',
          'Wallet list + wallet search controls',
          'Base policy presets and chain controls',
        ],
      },
    ],
  },
  {
    heading: 'Growth',
    items: [
      {
        title: 'Growth',
        description: 'Usage-based pricing as wallet adoption grows past launch volume.',
        to: '/pricing/#growth',
        visual: 'plan',
        price: 'Usage-based',
        priceNote: '5K to 100K MAW',
        details: [
          'Standard API keys and webhook endpoints',
          'Wallet search and chain visibility controls',
          'Designed for scaling embedded wallet apps',
        ],
      },
    ],
  },
  {
    heading: 'Scale',
    items: [
      {
        title: 'Scale',
        description: 'Advanced controls and support for stricter operational requirements.',
        to: '/pricing/#scale',
        visual: 'plan',
        price: 'Volume discounts',
        priceNote: '100K+ MAW',
        details: [
          'Custom policy engine with staged rollouts',
          'Dedicated SLA, onboarding, and architecture reviews',
          'Advanced RBAC, audit logs, and export controls',
        ],
      },
    ],
  },
];

const productsDropdownPane: DropdownPane = {
  id: 'products',
  label: 'Products',
  layout: 'product-tiles',
  tiles: productDropdownTiles,
  cta: {
    icon: 'docs',
    title: 'Developer documentation',
    description: 'Build embedded wallets and policy-controlled signing flows.',
    label: 'Read docs',
    to: '/docs/getting-started/overview',
  },
};

const documentationDropdownPane: DropdownPane = {
  id: 'documentation',
  label: 'Documentation',
  layout: 'pricing-tiles',
  tiles: documentationDropdownTiles,
  cta: {
    icon: 'pricing',
    title: 'Plan pricing',
    description: 'Compare self-serve and enterprise wallet infrastructure packages.',
    label: 'Learn more',
    to: '/pricing/',
  },
};

const aboutDropdownPane: DropdownPane = {
  id: 'about',
  label: 'About Us',
  layout: 'sections',
  sections: aboutSections,
  cta: {
    icon: 'contact',
    title: 'Talk to the Seams team',
    description: 'Plan a wallet integration or review a security-sensitive flow.',
    label: 'Contact sales',
    to: '/contact/',
  },
};

const pricingDropdownPane: DropdownPane = {
  id: 'pricing',
  label: 'Pricing',
  layout: 'sections',
  sections: pricingSections,
  cta: {
    icon: 'contact',
    title: 'Talk to us',
    description: 'Plan pricing and deployment options with the Seams team.',
    label: 'Contact sales',
    to: '/contact/',
  },
};

const dropdownPanes: DropdownPane[] = [
  productsDropdownPane,
  documentationDropdownPane,
  aboutDropdownPane,
  pricingDropdownPane,
];

const primaryDropdownTriggers: DropdownTriggerConfig[] = [
  {
    id: 'products',
    label: 'Products',
  },
  {
    id: 'documentation',
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

function dropdownOrderIndex(id: DropdownId): number {
  switch (id) {
    case 'products':
      return 0;
    case 'documentation':
      return 1;
    case 'pricing':
      return 2;
    case 'about':
      return 3;
    default:
      return assertNever(id);
  }
}

function paneVisualStateFor(paneId: DropdownId, activeId: DropdownId | null): PaneVisualState {
  if (paneId === activeId) return { kind: 'active' };
  if (!activeId) return { kind: 'after' };
  return dropdownOrderIndex(paneId) < dropdownOrderIndex(activeId)
    ? { kind: 'before' }
    : { kind: 'after' };
}

function paneVisualStateClassName(state: PaneVisualState): string {
  switch (state.kind) {
    case 'active':
      return 'is-active';
    case 'before':
      return 'is-before';
    case 'after':
      return 'is-after';
    default:
      return assertNever(state);
  }
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
  const CLOSE_DELAY_MS = 120;
  const SCROLL_THRESHOLD_PX = 8;

  const { theme, setTheme } = useTheme();
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
  const openTimerRef = React.useRef<number | null>(null);
  const closeTimerRef = React.useRef<number | null>(null);
  const [openDropdown, setOpenDropdown] = React.useState<DropdownId | null>(null);
  const [hasScrolled, setHasScrolled] = React.useState<boolean>(false);
  const [localTheme, setLocalTheme] = React.useState<'light' | 'dark'>(() => readDocumentTheme());
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
          <ChevronDown
            size={16}
            className={`navbar-static__chevron${isOpen ? ' is-open' : ''}`}
            aria-hidden
          />
        </button>
      </div>
    );
  }

  function renderCtaIcon(icon: DropdownCtaIcon): React.JSX.Element {
    switch (icon) {
      case 'docs':
        return <BookOpen size={22} strokeWidth={1.8} aria-hidden />;
      case 'pricing':
        return (
          <span className="navbar-static__access-cta-symbol" aria-hidden>
            $
          </span>
        );
      case 'contact':
        return <MessageCircle size={22} strokeWidth={1.8} aria-hidden />;
      default:
        return assertNever(icon);
    }
  }

  function renderAccessCtaTile(
    paneId: DropdownId,
    cta: DropdownCtaTile,
    isActive: boolean,
  ): React.JSX.Element {
    const ctaProps = getNavLinkProps(cta.to);

    return (
      <a
        key={`${paneId}-cta`}
        className={`navbar-static__access-cta-tile navbar-static__access-cta-tile--${paneId}`}
        role="menuitem"
        href={ctaProps.href}
        onClick={ctaProps.onClick}
        tabIndex={isActive ? undefined : -1}
      >
        <span className="navbar-static__access-cta-copy">
          <span className="navbar-static__access-cta-icon">{renderCtaIcon(cta.icon)}</span>
          <span className="navbar-static__access-cta-text">
            <span className="navbar-static__access-cta-title">{cta.title}</span>
            <span className="navbar-static__access-cta-description">{cta.description}</span>
          </span>
        </span>
        <span className="navbar-static__access-cta-action" aria-hidden>
          <span>{cta.label}</span>
          <ArrowRightAnim size={14} />
        </span>
      </a>
    );
  }

  function renderNavbarTileImage(item: DropdownItem): React.JSX.Element {
    if (!item.imageDarkSrc) {
      return <img src={item.imageSrc} alt="" draggable={false} />;
    }

    return (
      <span className="navbar-static__themed-image">
        <img
          className="navbar-static__themed-image-light"
          src={item.imageSrc}
          alt=""
          draggable={false}
        />
        <img
          className="navbar-static__themed-image-dark"
          src={item.imageDarkSrc}
          alt=""
          draggable={false}
        />
      </span>
    );
  }

  function renderAccessPane(pane: DropdownPane): React.JSX.Element {
    const visualState = paneVisualStateFor(pane.id, openDropdown);
    const isActive = visualState.kind === 'active';
    const paneClassName = [
      'navbar-static__access-pane',
      paneVisualStateClassName(visualState),
    ].join(' ');

    const panelContent = (() => {
      switch (pane.layout) {
        case 'product-tiles': {
          const tiles = pane.tiles.map((tile) => {
            const tileProps = getNavLinkProps(tile.to);
            return (
              <a
                key={tile.id}
                className={`navbar-static__access-product-tile navbar-static__access-product-tile--${tile.id}`}
                role="menuitem"
                href={tileProps.href}
                onClick={tileProps.onClick}
                tabIndex={isActive ? undefined : -1}
              >
                <span className="navbar-static__access-product-copy">
                  <span className="navbar-static__access-product-title">{tile.title}</span>
                  <span className="navbar-static__access-product-description">
                    {tile.description}
                  </span>
                </span>
                <span className="navbar-static__access-product-visual" aria-hidden>
                  {renderNavbarTileImage(tile)}
                </span>
              </a>
            );
          });

          return [...tiles, renderAccessCtaTile(pane.id, pane.cta, isActive)];
        }
        case 'pricing-tiles': {
          const tiles = pane.tiles.map((tile) => {
            const tileProps = getNavLinkProps(tile.to);
            return (
              <a
                key={tile.id}
                className={`navbar-static__access-pricing-tile navbar-static__access-pricing-tile--${tile.id}`}
                role="menuitem"
                href={tileProps.href}
                onClick={tileProps.onClick}
                tabIndex={isActive ? undefined : -1}
              >
                <span className="navbar-static__access-pricing-visual" aria-hidden>
                  {renderNavbarTileImage(tile)}
                </span>
                <span className="navbar-static__access-pricing-copy">
                  <span className="navbar-static__access-pricing-title">{tile.title}</span>
                  <span className="navbar-static__access-pricing-description">
                    {tile.description}
                  </span>
                </span>
              </a>
            );
          });

          return [...tiles, renderAccessCtaTile(pane.id, pane.cta, isActive)];
        }
        case 'sections': {
          const sections = pane.sections.map((section) => (
            <section
              className={`navbar-static__access-section navbar-static__access-section--${pane.id}`}
              key={section.heading}
            >
              {pane.id === 'pricing' ? null : (
                <p className="navbar-static__access-section-title">{section.heading}</p>
              )}
              <div className="navbar-static__access-items">
                {section.items.map((item) => {
                  const itemProps = getNavLinkProps(item.to);

                  return (
                    <a
                      key={item.title}
                      className={`navbar-static__access-item${
                        item.visual === 'plan' ? ' navbar-static__access-item--plan' : ''
                      }`}
                      role="menuitem"
                      href={itemProps.href}
                      onClick={itemProps.onClick}
                      tabIndex={isActive ? undefined : -1}
                    >
                      {item.visual === 'image' ? (
                        <span className="navbar-static__access-visual" aria-hidden>
                          {renderNavbarTileImage(item)}
                        </span>
                      ) : (
                        <>
                          <span className="navbar-static__access-plan-kicker">{item.title}</span>
                          <span className="navbar-static__access-plan">
                            <span className="navbar-static__access-plan-price">{item.price}</span>
                            <span className="navbar-static__access-plan-note">
                              {item.priceNote}
                            </span>
                          </span>
                          <span className="navbar-static__access-plan-copy">
                            {item.description}
                          </span>
                          {item.details.length > 0 ? (
                            <span className="navbar-static__access-plan-details">
                              {item.details.map((detail) => (
                                <span className="navbar-static__access-plan-detail" key={detail}>
                                  {detail}
                                </span>
                              ))}
                            </span>
                          ) : null}
                        </>
                      )}
                      {item.visual === 'image' ? (
                        <span className="navbar-static__access-item-copy">
                          <span className="navbar-static__access-item-title">{item.title}</span>
                          <span className="navbar-static__access-item-description">
                            {item.description}
                          </span>
                        </span>
                      ) : null}
                    </a>
                  );
                })}
              </div>
            </section>
          ));

          return [...sections, renderAccessCtaTile(pane.id, pane.cta, isActive)];
        }
        default:
          return assertNever(pane);
      }
    })();

    return (
      <div
        key={pane.id}
        id={`navbar-dropdown-${pane.id}`}
        className={paneClassName}
        data-dropdown-view={pane.id}
        aria-hidden={!isActive}
      >
        <div className={`navbar-static__access-panel navbar-static__access-panel--${pane.id}`}>
          {panelContent}
        </div>
      </div>
    );
  }

  return (
    <nav ref={rootRef} className="navbar-static" aria-label="Primary">
      <div className={`navbar-static__shell${hasScrolled ? ' is-scrolled' : ''}`}>
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
          className={`navbar-static__access-popup${openDropdown ? ' is-open' : ''}`}
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
            <div className="navbar-static__access-grid-shell">
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
            {productDropdownTiles.map((tile) => {
              const tileProps = getNavLinkProps(tile.to);
              return (
                <a
                  key={tile.id}
                  className="navbar-static__mobile-subitem"
                  href={tileProps.href}
                  onClick={tileProps.onClick}
                >
                  <span>{tile.title}</span>
                  <small>{tile.description}</small>
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
            {documentationDropdownTiles.map((tile) => {
              const tileProps = getNavLinkProps(tile.to);
              return (
                <a
                  key={tile.id}
                  className="navbar-static__mobile-subitem"
                  href={tileProps.href}
                  onClick={tileProps.onClick}
                >
                  <span>{tile.title}</span>
                  <small>{tile.description}</small>
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
          {pricingSections.map((section) => (
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
