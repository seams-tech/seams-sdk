import { normalizeOptionalNonEmptyString } from '@shared/utils/normalize';

export function normalizeOptionalChannelToken(channelToken: unknown): string | undefined {
  return normalizeOptionalNonEmptyString(channelToken);
}

export function normalizeChannelToken(channelToken: unknown): string {
  return normalizeOptionalChannelToken(channelToken) || '';
}
