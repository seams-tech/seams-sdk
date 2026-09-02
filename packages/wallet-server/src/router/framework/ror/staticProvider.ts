import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RorOriginsProvider } from './provider';
import { sanitizeRorOrigins } from './normalize';

export class StaticRorOriginsProvider implements RorOriginsProvider {
  private readonly byRpId: Map<string, string[]>;

  constructor(input: { byRpId: Record<string, string[]> }) {
    this.byRpId = new Map<string, string[]>();
    const byRpId = input?.byRpId || {};
    for (const [rawRpId, rawOrigins] of Object.entries(byRpId)) {
      const rpId = toOptionalTrimmedString(rawRpId).toLowerCase();
      if (!rpId) continue;
      this.byRpId.set(rpId, sanitizeRorOrigins(rawOrigins));
    }
  }

  async getAllowedOrigins(input: { rpId: string }): Promise<string[]> {
    const rpId = toOptionalTrimmedString(input.rpId).toLowerCase();
    if (!rpId) return [];
    return this.byRpId.get(rpId) || [];
  }
}
