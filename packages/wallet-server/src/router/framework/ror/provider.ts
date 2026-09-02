import { toOptionalTrimmedString } from '@shared/utils/validation';
import { normalizeRorHost } from './normalize';

export interface RorOriginsProvider {
  getAllowedOrigins(input: { rpId: string; host?: string }): Promise<string[]>;
}

export type RouterApiRorOptions = {
  provider: RorOriginsProvider;
  rpId?: string;
  rpIdByHost?: Record<string, string>;
};

export function validateRouterApiRorOptions(ror: RouterApiRorOptions): void {
  if (!ror || typeof ror !== 'object') {
    throw new Error('[router.ror] Invalid ROR options: expected object');
  }
  if (!ror.provider || typeof ror.provider.getAllowedOrigins !== 'function') {
    throw new Error('[router.ror] Invalid ROR options: provider.getAllowedOrigins is required');
  }

  const staticRpId = toOptionalTrimmedString(ror.rpId).toLowerCase();
  const hasStaticRpId = Boolean(staticRpId);

  const hostMap = ror.rpIdByHost;
  const hasHostMap = Boolean(
    hostMap && typeof hostMap === 'object' && Object.keys(hostMap).length > 0,
  );

  if (hasStaticRpId === hasHostMap) {
    throw new Error('[router.ror] Configure exactly one RP ID strategy: `rpId` or `rpIdByHost`');
  }

  if (hasHostMap) {
    for (const [rawHost, rawRpId] of Object.entries(hostMap || {})) {
      const host = normalizeRorHost(rawHost);
      const rpId = toOptionalTrimmedString(rawRpId).toLowerCase();
      if (!host || !rpId) {
        throw new Error(
          '[router.ror] Invalid `rpIdByHost` entry: host and rpId must be non-empty strings',
        );
      }
    }
  }
}

export function resolveRorRpId(input: {
  ror: RouterApiRorOptions | undefined;
  host?: string;
}): string | null {
  const ror = input.ror;
  if (!ror) return null;

  const staticRpId = toOptionalTrimmedString(ror.rpId).toLowerCase();
  if (staticRpId) return staticRpId;

  const hostMap = ror.rpIdByHost;
  if (!hostMap || typeof hostMap !== 'object') return null;

  const host = normalizeRorHost(input.host);
  if (!host) return null;

  const rpId = toOptionalTrimmedString(hostMap[host]).toLowerCase();
  return rpId || null;
}
