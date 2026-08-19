import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(() => {
  const appSrc = fileURLToPath(new URL('./src', import.meta.url));
  return {
    base: '/dashboard/',
    plugins: [react()],
    server: {
      host: 'localhost',
      port: 3601,
      strictPort: true,
    },
    resolve: {
      alias: {
        '@core': `${appSrc}/core`,
        '@wallet-product': `${appSrc}/products/wallet`,
        '@app': `${appSrc}/app`,
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: true,
    },
  };
});
