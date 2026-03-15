export const MACHINE_API_KEY_SCOPES = ['accounts.create', 'wallets.read'] as const;

export type MachineApiKeyScope = (typeof MACHINE_API_KEY_SCOPES)[number];

export interface MachineApiKeyScopeOption {
  value: MachineApiKeyScope;
  label: string;
  description: string;
}

const MACHINE_API_KEY_SCOPE_METADATA: Record<
  MachineApiKeyScope,
  Omit<MachineApiKeyScopeOption, 'value'>
> = {
  'accounts.create': {
    label: 'Create accounts',
    description: 'Allows backend bootstrap flows to create accounts.',
  },
  'wallets.read': {
    label: 'Read wallets',
    description: 'Allows backend access to list, search, and read wallets within the key environment.',
  },
};

export const MACHINE_API_KEY_SCOPE_OPTIONS: readonly MachineApiKeyScopeOption[] =
  MACHINE_API_KEY_SCOPES.map((value) => ({
    value,
    ...MACHINE_API_KEY_SCOPE_METADATA[value],
  }));

const MACHINE_API_KEY_SCOPE_SET = new Set<string>(MACHINE_API_KEY_SCOPES);

export function isMachineApiKeyScope(value: string): value is MachineApiKeyScope {
  return MACHINE_API_KEY_SCOPE_SET.has(value);
}
