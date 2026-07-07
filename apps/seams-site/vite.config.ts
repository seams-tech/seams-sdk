import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { seamsWallet } from '@seams/sdk/plugins/vite';

/**
 * Do NOT use optional chaining or dynamic access such as `import.meta?.env`
 * or `import.meta["env"]`. Those patterns prevent Vite's static analysis
 * and will yield `undefined` at runtime without errors.
 * See: https://vite.dev/guide/env-and-mode
 */

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const appSrc = fileURLToPath(new URL('./src', import.meta.url));
  const appPublic = fileURLToPath(new URL('./src/public', import.meta.url));
  const appNodeModules = fileURLToPath(new URL('./node_modules', import.meta.url));
  const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url));
  const cacheDir = env.VITE_CACHE_DIR || undefined;
  // Bitwarden and other password managers inject extension iframes/scripts that are blocked
  // by COEP=require-corp on the host page. Default to COEP off for the docs site; switch
  // back on explicitly when you need cross-origin isolation testing.
  const coepMode = (env.VITE_COEP_MODE === 'strict' ? 'strict' : 'off') as 'strict' | 'off';
  // Make VITE_* visible to Node-side dev plugins
  if (env.VITE_WALLET_ORIGIN) process.env.VITE_WALLET_ORIGIN = env.VITE_WALLET_ORIGIN;
  if (env.VITE_DOCS_ORIGIN) process.env.VITE_DOCS_ORIGIN = env.VITE_DOCS_ORIGIN;
  if (env.VITE_ROR_ALLOWED_ORIGINS)
    process.env.VITE_ROR_ALLOWED_ORIGINS = env.VITE_ROR_ALLOWED_ORIGINS;
  return {
    clearScreen: false,
    logLevel: 'info',
    cacheDir,
    publicDir: appPublic,
    server: {
      port: 3600,
      host: 'localhost',
      // Allow access via reverse-proxied hosts (Caddy) and Bonjour (.local)
      // Needed to avoid Vite's DNS‑rebinding protection blocking mDNS hosts
      allowedHosts: ['localhost', 'pta-m4.local'],
      open: false,
      fs: {
        allow: [
          workspaceRoot,
          // Allow serving files from entire workspace including SDK
        ],
      },
    },
    plugins: [
      react(),
      // Web3Authn dev integration: wallet server (serve SDK + wallet HTML + headers)
      // Build: emit _headers for COOP + Permissions‑Policy (and optional COEP/CORP when enabled); wallet HTML gets strict CSP.
      seamsWallet({
        enableDebugRoutes: true,
        sdkBasePath: env.VITE_SDK_BASE_PATH || '/sdk',
        walletServicePath: env.VITE_WALLET_SERVICE_PATH || '/wallet-service',
        walletOrigin: env.VITE_WALLET_ORIGIN,
        emitHeaders: true,
        coepMode,
        // Build-time: emit _headers for Cloudflare Pages/Netlify with COOP/COEP and
        // a Permissions-Policy delegating WebAuthn to the wallet origin.
        // If your CI already writes a _headers file, this plugin will no-op.
      }),
    ],
    resolve: {
      alias: [
        { find: '@', replacement: appSrc },
        { find: /^react$/, replacement: `${appNodeModules}/react/index.js` },
        {
          find: /^react\/jsx-runtime$/,
          replacement: `${appNodeModules}/react/jsx-runtime.js`,
        },
        {
          find: /^react\/jsx-dev-runtime$/,
          replacement: `${appNodeModules}/react/jsx-dev-runtime.js`,
        },
        { find: /^react-dom$/, replacement: `${appNodeModules}/react-dom/index.js` },
        {
          find: /^react-dom\/client$/,
          replacement: `${appNodeModules}/react-dom/client.js`,
        },
      ],
      dedupe: ['react', 'react-dom'],
    },
  };
});
