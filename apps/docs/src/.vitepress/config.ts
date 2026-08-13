import { defineConfig, type DefaultTheme } from 'vitepress';

const docsOrigin = (process.env.VITE_DOCS_ORIGIN || 'https://docs.seams.sh').replace(/\/$/, '');

function pageUrl(page: string): string {
  const route = page.replace(/(?:^|\/)index\.md$/, '').replace(/\.md$/, '');
  return route ? `${docsOrigin}/${route}` : docsOrigin;
}

const startHereSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'Start here',
    items: [
      { text: 'Overview and install', link: '/' },
      { text: 'Create a wallet', link: '/getting-started/create-wallet' },
      { text: 'Sign with policy', link: '/getting-started/sign-with-policy' },
      { text: 'Recovery and export', link: '/guides/recovery-export-and-rotation' },
      { text: 'Delegate or rotate', link: '/getting-started/delegate-or-rotate' },
    ],
  },
  {
    text: 'Continue building',
    collapsed: true,
    items: [{ text: 'Theming', link: '/getting-started/theming' }],
  },
];

const guidesSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'Guides',
    items: [
      { text: 'Overview', link: '/guides/' },
      { text: 'Authentication', link: '/guides/authentication' },
      { text: 'Embedded wallets', link: '/guides/embedded-wallets' },
      { text: 'Policies and mandates', link: '/guides/policies-and-mandates' },
      {
        text: 'Wallet sessions and signing lanes',
        link: '/guides/wallet-sessions-and-signing-lanes',
      },
      { text: 'Delegated agents', link: '/guides/delegated-agents' },
      { text: 'Linked devices', link: '/guides/linked-devices' },
      {
        text: 'Recovery, export, and rotation',
        link: '/guides/recovery-export-and-rotation',
      },
      { text: 'Theming', link: '/guides/theming' },
    ],
  },
];

const referenceSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'SDK reference',
    items: [
      { text: 'Overview', link: '/reference/' },
      { text: '@seams/sdk', link: '/reference/core' },
      { text: '@seams/sdk/react', link: '/reference/react' },
      { text: '@seams/sdk/advanced', link: '/reference/advanced' },
      { text: '@seams/sdk/threshold', link: '/reference/threshold' },
      { text: '@seams/sdk/runtime', link: '/reference/runtime' },
      { text: 'Configuration', link: '/reference/configuration' },
      { text: 'Results and errors', link: '/reference/results-and-errors' },
      { text: 'Events and progress', link: '/reference/events-and-progress' },
    ],
  },
];

const conceptsSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'Concepts and security',
    items: [
      { text: 'Overview', link: '/concepts/' },
      { text: 'Architecture', link: '/concepts/architecture' },
      { text: 'Auth planes', link: '/concepts/auth-planes' },
      { text: 'Glossary', link: '/concepts/glossary' },
      {
        text: 'Wallet infrastructure comparison',
        link: '/concepts/wallet-infrastructure-comparison',
      },
      {
        text: 'Policy',
        link: '/concepts/policy/',
        collapsed: true,
        items: [
          { text: 'Overview', link: '/concepts/policy/' },
          { text: 'Mandates', link: '/concepts/policy/mandates' },
          { text: 'Credentials and proofs', link: '/concepts/policy/credentials-and-proofs' },
        ],
      },
      {
        text: 'Custody model',
        link: '/concepts/custody/',
        collapsed: true,
        items: [
          { text: 'Overview', link: '/concepts/custody/' },
          { text: 'Wallet iframe', link: '/concepts/custody/wallet-iframe' },
          { text: 'Recovery and export', link: '/concepts/custody/recovery-and-export' },
        ],
      },
      {
        text: 'Sessions',
        link: '/concepts/sessions/',
        collapsed: true,
        items: [
          { text: 'Overview', link: '/concepts/sessions/' },
          { text: 'Signing lanes', link: '/concepts/sessions/signing-lanes' },
          { text: 'Wallet sessions', link: '/concepts/sessions/wallet-sessions' },
          { text: 'Sealed refresh', link: '/concepts/sessions/sealed-refresh' },
          { text: 'Nonce lanes', link: '/concepts/sessions/nonce-lanes' },
        ],
      },
      {
        text: 'Threshold signing',
        link: '/concepts/threshold-signing/',
        collapsed: true,
        items: [
          { text: 'Overview', link: '/concepts/threshold-signing/' },
          { text: 'Router A/B', link: '/concepts/threshold-signing/router-ab' },
          { text: 'Streaming Yao A/B', link: '/concepts/threshold-signing/streaming-yao-ab' },
          {
            text: 'Blind deterministic derivation',
            link: '/concepts/threshold-signing/blind-deterministic-derivation',
          },
          {
            text: 'Serverless threshold signing',
            link: '/concepts/threshold-signing/serverless-threshold-signing',
          },
          { text: 'Ed25519', link: '/concepts/threshold-signing/ed25519' },
          { text: 'EVM ECDSA', link: '/concepts/threshold-signing/evm-ecdsa' },
        ],
      },
      {
        text: 'Delegation',
        link: '/concepts/delegation/',
        collapsed: true,
        items: [
          { text: 'Overview', link: '/concepts/delegation/' },
          { text: 'Key rotation', link: '/concepts/delegation/key-rotation' },
          { text: 'Linked devices', link: '/concepts/delegation/linked-devices' },
          { text: 'Delegated agents', link: '/concepts/delegation/delegated-agents' },
        ],
      },
    ],
  },
  {
    text: 'Auth methods',
    collapsed: true,
    items: [
      { text: 'Overview', link: '/concepts/auth-methods/' },
      { text: 'Passkeys', link: '/concepts/auth-methods/passkeys' },
      { text: 'Email OTP', link: '/concepts/auth-methods/email-otp' },
      { text: 'VoiceID', link: '/concepts/auth-methods/voiceid' },
    ],
  },
];

const advancedConceptsSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'Advanced protocol',
    items: [
      { text: 'Overview', link: '/concepts/advanced/' },
      {
        text: 'Route auth and deployment',
        link: '/concepts/advanced/route-auth-and-deployment',
      },
      { text: 'Router A/B protocol', link: '/concepts/advanced/router-ab-protocol' },
      { text: 'Rotation ceremonies', link: '/concepts/advanced/rotation-ceremonies' },
      { text: 'Diagram sources', link: '/concepts/advanced/diagram-sources' },
    ],
  },
];

const deployAndOperateSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'Deploy and operate',
    items: [
      { text: 'Overview', link: '/deploy-and-operate/' },
      { text: 'Hosted integration', link: '/deploy-and-operate/hosted-integration' },
      { text: 'Security boundaries', link: '/deploy-and-operate/security-boundaries' },
      { text: 'Environment', link: '/deploy-and-operate/environment' },
      { text: 'Production checklist', link: '/deploy-and-operate/production-checklist' },
      { text: 'Observability and audit', link: '/deploy-and-operate/observability-and-audit' },
      { text: 'Troubleshooting', link: '/deploy-and-operate/troubleshooting' },
    ],
  },
];

const useCasesSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'Use cases',
    items: [
      { text: 'Overview', link: '/use-cases/' },
      { text: 'Ecommerce agents', link: '/use-cases/ecommerce-agents' },
      { text: 'iPhone access passes', link: '/use-cases/iphone-access-passes' },
      { text: 'Shipping agent credentials', link: '/use-cases/shipping-agent-credentials' },
      { text: 'Embedded device credentials', link: '/use-cases/embedded-device-credentials' },
    ],
  },
];

export default defineConfig({
  base: '/',
  cleanUrls: true,
  appearance: false,
  lastUpdated: true,
  title: 'Seams',
  description: 'Key and credential infrastructure for policy-bound digital authority',
  sitemap: {
    hostname: docsOrigin,
    transformItems: (items) => items.filter((item) => !item.url.endsWith('/404')),
  },
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
    ['meta', { property: 'og:site_name', content: 'Seams docs' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { name: 'twitter:card', content: 'summary' }],
  ],
  transformHead({ page, title, description }) {
    const canonicalUrl = pageUrl(page);
    return [
      ['link', { rel: 'canonical', href: canonicalUrl }],
      ['meta', { property: 'og:title', content: title }],
      ['meta', { property: 'og:description', content: description }],
      ['meta', { property: 'og:url', content: canonicalUrl }],
      ['meta', { name: 'twitter:title', content: title }],
      ['meta', { name: 'twitter:description', content: description }],
    ];
  },
  markdown: {
    theme: 'github-light-high-contrast',
    languageAlias: {
      caddy: 'nginx',
    },
  },
  themeConfig: {
    siteTitle: 'Seams docs',
    logo: {
      src: '/seams-v9/svg/seams-mark-black.svg',
      alt: 'Seams',
    },
    lastUpdated: { text: 'Last updated' },
    outline: [2, 3],
    search: { provider: 'local' },
    nav: [
      { text: 'Guides', link: '/guides/' },
      { text: 'SDK reference', link: '/reference/' },
      { text: 'Concepts and security', link: '/concepts/' },
      {
        text: 'More',
        items: [
          { text: 'Deploy and operate', link: '/deploy-and-operate/' },
          { text: 'Use cases', link: '/use-cases/' },
        ],
      },
    ],
    sidebar: {
      '/getting-started/': startHereSidebar,
      '/guides/': guidesSidebar,
      '/reference/': referenceSidebar,
      '/concepts/advanced/': advancedConceptsSidebar,
      '/concepts/': conceptsSidebar,
      '/deploy-and-operate/': deployAndOperateSidebar,
      '/use-cases/': useCasesSidebar,
      '/': startHereSidebar,
    },
  },
  vite: {
    clearScreen: false,
    logLevel: 'info',
    server: {
      host: 'localhost',
      port: 5222,
      allowedHosts: ['docs.localhost', 'localhost', 'pta-m4.local'],
    },
  },
});
