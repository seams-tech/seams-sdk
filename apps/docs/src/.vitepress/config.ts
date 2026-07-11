import { defineConfig } from 'vitepress';

export default defineConfig({
  base: '/',
  title: 'Seams',
  description: 'Key and credential infrastructure for policy-bound digital authority',
  head: [
    ['link', { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.googleapis.com' }],
    ['link', { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' }],
    [
      'link',
      {
        rel: 'preload',
        as: 'style',
        href: 'https://fonts.googleapis.com/css2?family=Hanken+Grotesk:ital,wght@0,400;0,500;0,600;0,700;1,400;1,500;1,600;1,700&display=fallback',
      },
    ],
    [
      'link',
      {
        rel: 'stylesheet',
        href: 'https://fonts.googleapis.com/css2?family=Hanken+Grotesk:ital,wght@0,400;0,500;0,600;0,700;1,400;1,500;1,600;1,700&display=fallback',
      },
    ],
  ],
  markdown: {
    languageAlias: {
      caddy: 'nginx',
    },
  },
  themeConfig: {
    siteTitle: 'Seams.xyz',
    logoLink: 'https://localhost',
    outline: [2, 3],
    search: { provider: 'local' },
    nav: [
      { text: 'Getting Started', link: '/getting-started/' },
      { text: 'Concepts', link: '/concepts/' },
    ],
    sidebar: [
      {
        text: 'Getting Started',
        collapsed: false,
        items: [
          { text: 'Overview', link: '/getting-started/' },
          { text: 'Create A Wallet', link: '/getting-started/create-wallet' },
          { text: 'Sign With Policy', link: '/getting-started/sign-with-policy' },
          {
            text: 'Delegate Or Rotate',
            link: '/getting-started/delegate-or-rotate',
          },
          { text: 'Theming', link: '/getting-started/theming' },
          {
            text: 'Other Applications',
            collapsed: false,
            items: [
              {
                text: 'iPhone Access Passes',
                link: '/getting-started/iphone-access-passes',
              },
              {
                text: 'Shipping Agent Credentials',
                link: '/getting-started/shipping-agent-credentials',
              },
              {
                text: 'Embedded Device Credentials',
                link: '/getting-started/embedded-device-credentials',
              },
            ],
          },
        ],
      },
      {
        text: 'Concepts',
        collapsed: false,
        items: [
          { text: 'Overview', link: '/concepts/' },
          { text: 'Architecture', link: '/concepts/architecture' },
          {
            text: 'Wallet Infrastructure Comparison',
            link: '/concepts/wallet-infrastructure-comparison',
          },
          { text: 'Glossary', link: '/concepts/glossary' },
          { text: 'Auth Planes', link: '/concepts/auth-planes' },
          {
            text: 'Policy',
            collapsed: false,
            items: [
              { text: 'Overview', link: '/concepts/policy/' },
              { text: 'Mandates', link: '/concepts/policy/mandates' },
              {
                text: 'Credentials And Proofs',
                link: '/concepts/policy/credentials-and-proofs',
              },
            ],
          },
          {
            text: 'Custody',
            collapsed: false,
            items: [
              { text: 'Overview', link: '/concepts/custody/' },
              { text: 'Wallet Iframe', link: '/concepts/custody/wallet-iframe' },
              {
                text: 'Recovery And Export',
                link: '/concepts/custody/recovery-and-export',
              },
            ],
          },
          {
            text: 'Threshold Signing',
            collapsed: false,
            items: [
              { text: 'Overview', link: '/concepts/threshold-signing/' },
              { text: 'Router A/B', link: '/concepts/threshold-signing/router-ab' },
              {
                text: 'Streaming Yao A/B',
                link: '/concepts/threshold-signing/streaming-yao-ab',
              },
              {
                text: 'Serverless Threshold Signing',
                link: '/concepts/threshold-signing/serverless-threshold-signing',
              },
              {
                text: 'Ed25519',
                link: '/concepts/threshold-signing/ed25519',
              },
              {
                text: 'EVM ECDSA',
                link: '/concepts/threshold-signing/evm-ecdsa',
              },
            ],
          },
          {
            text: 'Sessions',
            collapsed: false,
            items: [
              { text: 'Overview', link: '/concepts/sessions/' },
              { text: 'Signing Lanes', link: '/concepts/sessions/signing-lanes' },
              { text: 'Wallet Sessions', link: '/concepts/sessions/wallet-sessions' },
              { text: 'Sealed Refresh', link: '/concepts/sessions/sealed-refresh' },
              { text: 'Nonce Lanes', link: '/concepts/sessions/nonce-lanes' },
            ],
          },
          {
            text: 'Auth Methods',
            collapsed: false,
            items: [
              { text: 'Overview', link: '/concepts/auth-methods/' },
              { text: 'Passkeys', link: '/concepts/auth-methods/passkeys' },
              { text: 'Email OTP', link: '/concepts/auth-methods/email-otp' },
              { text: 'VoiceID', link: '/concepts/auth-methods/voiceid' },
            ],
          },
          {
            text: 'Delegation',
            collapsed: false,
            items: [
              { text: 'Overview', link: '/concepts/delegation/' },
              { text: 'Key Rotation', link: '/concepts/delegation/key-rotation' },
              { text: 'Linked Devices', link: '/concepts/delegation/linked-devices' },
              {
                text: 'Delegated Agents',
                link: '/concepts/delegation/delegated-agents',
              },
            ],
          },
          {
            text: 'Advanced',
            collapsed: true,
            items: [
              { text: 'Overview', link: '/concepts/advanced/' },
              {
                text: 'Route Auth And Deployment',
                link: '/concepts/advanced/route-auth-and-deployment',
              },
              {
                text: 'Router A/B Protocol',
                link: '/concepts/advanced/router-ab-protocol',
              },
              {
                text: 'Rotation Ceremonies',
                link: '/concepts/advanced/rotation-ceremonies',
              },
              {
                text: 'Diagram Sources',
                link: '/concepts/advanced/diagram-sources',
              },
            ],
          },
        ],
      },
    ],
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
