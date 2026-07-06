import { expect, test } from '@playwright/test';
import { parseConfiguredRorOrigins, resolveRorOrigins } from '@/plugins/plugin-utils';
import { seamsHeaders } from '@/plugins/vite';

type Middleware = (req: any, res: any, next: () => void) => void;

function collectPluginMiddlewares(plugin: ReturnType<typeof seamsHeaders>): Middleware[] {
  const middlewares: Middleware[] = [];
  plugin.configureServer?.({
    middlewares: {
      use(fn: Middleware) {
        middlewares.push(fn);
      },
    },
  });
  return middlewares;
}

function runMiddlewares(middlewares: readonly Middleware[], req: any, res: any) {
  let index = 0;
  const next = () => {
    const middleware = middlewares[index++];
    if (middleware) middleware(req, res, next);
  };
  next();
}

test.describe('plugin ROR origin resolution', () => {
  test('includes the wallet origin even when the explicit ROR allowlist omits it', () => {
    expect(
      resolveRorOrigins({
        configuredOrigins: parseConfiguredRorOrigins('https://docs.localhost'),
        docsOrigin: 'https://docs.localhost',
        walletOrigin: 'https://localhost:8443',
      }),
    ).toEqual(['https://docs.localhost', 'https://localhost:8443']);
  });

  test('normalizes and rejects invalid related origins', () => {
    expect(
      resolveRorOrigins({
        configuredOrigins: parseConfiguredRorOrigins(
          'https://LOCALHOST:8443, http://localhost:3600, http://example.com, not-a-url',
        ),
        docsOrigin: '',
        walletOrigin: '',
      }),
    ).toEqual(['https://localhost:8443', 'http://localhost:3600']);
  });

  test('Vite well-known route includes the configured wallet origin', () => {
    const previousAllowedOrigins = process.env.VITE_ROR_ALLOWED_ORIGINS;
    const previousDocsOrigin = process.env.VITE_DOCS_ORIGIN;
    process.env.VITE_ROR_ALLOWED_ORIGINS = '';
    process.env.VITE_DOCS_ORIGIN = '';

    try {
      const plugin = seamsHeaders({ walletOrigin: 'https://localhost:8443' });
      const middlewares = collectPluginMiddlewares(plugin);
      let body = '';
      const headers: Record<string, string> = {};
      const res = {
        statusCode: 0,
        setHeader(key: string, value: string) {
          headers[key.toLowerCase()] = value;
        },
        end(value?: string) {
          body = String(value || '');
        },
      };

      runMiddlewares(middlewares, { url: '/.well-known/webauthn' }, res);

      expect(res.statusCode).toBe(200);
      expect(headers['content-type']).toBe('application/json; charset=utf-8');
      expect(JSON.parse(body)).toEqual({ origins: ['https://localhost:8443'] });
    } finally {
      if (previousAllowedOrigins === undefined) delete process.env.VITE_ROR_ALLOWED_ORIGINS;
      else process.env.VITE_ROR_ALLOWED_ORIGINS = previousAllowedOrigins;
      if (previousDocsOrigin === undefined) delete process.env.VITE_DOCS_ORIGIN;
      else process.env.VITE_DOCS_ORIGIN = previousDocsOrigin;
    }
  });
});
