import { defineConfig } from 'vitepress';

export default defineConfig({
  base: '/',
  title: 'Tatchi Passkey',
  description: 'A serverless embedded wallet SDK',
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
    siteTitle: 'Tatchi.xyz',
    logoLink: 'https://example.localhost',
    outline: [2, 3],
    search: { provider: 'local' },
    nav: [
      { text: 'Getting Started', link: '/getting-started/overview' },
      { text: 'Concepts', link: '/concepts/' },
    ],
    sidebar: [
      {
        text: 'Getting Started',
        collapsed: false,
        items: [
          { text: 'Overview', link: '/getting-started/overview' },
          { text: 'Installation', link: '/getting-started/installation' },
          {
            text: 'Quick Start: Next Steps',
            link: '/getting-started/next-steps',
          },
          { text: 'React Recipes', link: '/getting-started/react-recipes' },
          {
            text: 'Other Frameworks',
            collapsed: true,
            items: [
              { text: 'Next.js', link: '/getting-started/other-frameworks#next-js' },
              { text: 'Vue 3', link: '/getting-started/other-frameworks#vue-3' },
              { text: 'Svelte', link: '/getting-started/other-frameworks#svelte' },
              {
                text: 'Vanilla JS / Express',
                link: '/getting-started/other-frameworks#vanilla-js-express',
              },
            ],
          },
        ],
      },
      {
        text: 'Concepts',
        collapsed: false,
        items: [
          { text: 'Design Goals', link: '/concepts/' },
          { text: 'Architecture', link: '/concepts/architecture' },
          { text: 'Threshold Signing', link: '/concepts/threshold-signing' },
          { text: 'Passkey Scope', link: '/concepts/passkey-scope' },
          { text: 'SecureConfirm Sessions', link: '/concepts/secureconfirm-sessions' },
          { text: 'SecureConfirm WebAuthn', link: '/concepts/secureconfirm-webauthn' },
          { text: 'Security Model', link: '/concepts/security-model' },
          { text: 'Nonce Manager', link: '/concepts/nonce-manager' },
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
      allowedHosts: ['docs.example.localhost', 'example.localhost', 'pta-m4.local'],
    },
  },
});
