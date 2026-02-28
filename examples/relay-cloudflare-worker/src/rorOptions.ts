type CreateRorOptionsInput = {
  expectedOrigin?: string;
  expectedWalletOrigin?: string;
  rorRpId?: string;
  rorAllowedOrigins?: string;
};

function normalizeCsv(values: string): string[] {
  return values
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

export function hostnameFromOrigin(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function sanitizeOrigins(values: string[]): string[] {
  const out = new Set<string>();
  for (const raw of values) {
    try {
      const u = new URL(String(raw || '').trim());
      const scheme = u.protocol;
      const host = u.hostname.toLowerCase();
      if (!host) continue;
      if (scheme !== 'https:' && !(scheme === 'http:' && host === 'localhost')) continue;
      if ((u.pathname && u.pathname !== '/') || u.search || u.hash) continue;
      const port = u.port ? `:${u.port}` : '';
      out.add(`${scheme}//${host}${port}`);
    } catch {}
  }
  return Array.from(out);
}

export function createRorOptions(input: CreateRorOptionsInput) {
  const expectedOrigin = String(input.expectedOrigin || '').trim();
  const expectedWalletOrigin = String(input.expectedWalletOrigin || '').trim();
  const rpId = String(input.rorRpId || hostnameFromOrigin(expectedWalletOrigin))
    .trim()
    .toLowerCase();
  if (!rpId) return undefined;

  const origins = sanitizeOrigins([
    expectedOrigin,
    expectedWalletOrigin,
    ...normalizeCsv(String(input.rorAllowedOrigins || '')),
  ]);

  return {
    rpId,
    provider: {
      getAllowedOrigins: async (providerInput: { rpId: string; host?: string }) =>
        providerInput.rpId === rpId ? origins : [],
    },
  };
}
