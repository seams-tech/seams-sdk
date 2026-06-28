import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RouterApiRorOptions } from './provider';
import { StaticRorOriginsProvider } from './staticProvider';
import { normalizeCsv, sanitizeRorOrigins } from './normalize';

export type CreateRorOptionsInput = {
  expectedOrigin?: unknown;
  expectedWalletOrigin?: unknown;
  rorRpId?: unknown;
  rorAllowedOrigins?: unknown;
};

function hostnameFromOrigin(originRaw: unknown): string {
  const origin = toOptionalTrimmedString(originRaw);
  if (!origin) return '';
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

export function createRorOptions(input: CreateRorOptionsInput): RouterApiRorOptions | undefined {
  const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
  const expectedWalletOrigin = toOptionalTrimmedString(input.expectedWalletOrigin);
  const rpId = toOptionalTrimmedString(input.rorRpId || hostnameFromOrigin(expectedWalletOrigin))
    .toLowerCase();
  if (!rpId) return undefined;

  const origins = sanitizeRorOrigins([
    expectedOrigin,
    expectedWalletOrigin,
    ...normalizeCsv(input.rorAllowedOrigins),
  ]);

  return {
    rpId,
    provider: new StaticRorOriginsProvider({
      byRpId: {
        [rpId]: origins,
      },
    }),
  };
}
