import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Do NOT use optional chaining or dynamic access such as `import.meta?.env`
 * or `import.meta["env"]`. Those patterns prevent Vite's static analysis
 * and will yield `undefined` at runtime without errors.
 * See: https://vite.dev/guide/env-and-mode
 */

export default defineConfig(({ mode }) => {
  const workspaceRoot = fileURLToPath(new URL('../..', import.meta.url));
  const env = loadEnv(mode, workspaceRoot, '');

  /* Production builds must receive the public signing mode and relayer URL from CI. */
  const requiredEnvKeys = ['VITE_SIGNING_SESSION_PERSISTENCE_MODE', 'VITE_RELAYER_URL'];
  const missingEnvKeys = requiredEnvKeys.filter((key) => !String(env[key] || '').trim());
  if (missingEnvKeys.length > 0) {
    console.warn(
      `\n[seams-site] WARNING: missing env vars: ${missingEnvKeys.join(', ')}.\n` +
        '[seams-site] Add them to the root .env.local (see apps/seams-site/env.example) — ' +
        'without them, signing-session sealing is disabled.\n',
    );
  }

  const appSrc = fileURLToPath(new URL('./src', import.meta.url));
  const appPublic = fileURLToPath(new URL('./src/public', import.meta.url));
  const workspaceNodeModules = fileURLToPath(new URL('../../node_modules', import.meta.url));
  const cacheDir = env.VITE_CACHE_DIR || undefined;

  return {
    envDir: workspaceRoot,
    clearScreen: false,
    logLevel: 'info',
    cacheDir,
    publicDir: appPublic,
    server: {
      port: 3600,
      host: 'localhost',
      strictPort: true,
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
    plugins: [react()],
    resolve: {
      alias: [
        { find: '@', replacement: appSrc },
        { find: /^react$/, replacement: `${workspaceNodeModules}/react/index.js` },
        {
          find: /^react\/jsx-runtime$/,
          replacement: `${workspaceNodeModules}/react/jsx-runtime.js`,
        },
        {
          find: /^react\/jsx-dev-runtime$/,
          replacement: `${workspaceNodeModules}/react/jsx-dev-runtime.js`,
        },
        { find: /^react-dom$/, replacement: `${workspaceNodeModules}/react-dom/index.js` },
        {
          find: /^react-dom\/client$/,
          replacement: `${workspaceNodeModules}/react-dom/client.js`,
        },
      ],
      dedupe: ['react', 'react-dom'],
    },
  };
});
