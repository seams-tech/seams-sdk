import { toOptionalTrimmedString } from '@shared/utils/validation';

export type AuthServiceConfigSource = Record<string, unknown> | null | undefined;

export function isAuthServiceProductionEnvironment(): boolean {
  const raw = String((globalThis as { process?: { env?: Record<string, unknown> } }).process?.env?.NODE_ENV || '')
    .trim()
    .toLowerCase();
  return raw === 'production';
}

export function readAuthServiceConfigValue(input: {
  thresholdStore: AuthServiceConfigSource;
  name: string;
}): string {
  const fromStoreConfig = toOptionalTrimmedString(input.thresholdStore?.[input.name]);
  if (fromStoreConfig) return fromStoreConfig;
  return (
    toOptionalTrimmedString(
      (globalThis as { process?: { env?: Record<string, unknown> } }).process?.env?.[input.name],
    ) || ''
  );
}
