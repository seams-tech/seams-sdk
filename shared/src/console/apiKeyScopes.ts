export const API_CREDENTIAL_SCOPES = [
  'accounts.create',
  'wallets.read',
  'wallets.signers.create',
] as const;

export type ApiCredentialScope = (typeof API_CREDENTIAL_SCOPES)[number];

export interface ApiCredentialScopeOption {
  value: ApiCredentialScope;
  label: string;
  description: string;
}

const API_CREDENTIAL_SCOPE_METADATA: Record<
  ApiCredentialScope,
  Omit<ApiCredentialScopeOption, 'value'>
> = {
  'accounts.create': {
    label: 'Create accounts',
    description: 'Allows backend bootstrap flows to create accounts.',
  },
  'wallets.read': {
    label: 'Read wallets',
    description: 'Allows backend access to list, search, and read wallets within the key environment.',
  },
  'wallets.signers.create': {
    label: 'Create wallet signers',
    description: 'Allows backend bootstrap flows to attach new wallet signers.',
  },
};

export const API_CREDENTIAL_SCOPE_OPTIONS: readonly ApiCredentialScopeOption[] =
  API_CREDENTIAL_SCOPES.map((value) => ({
    value,
    ...API_CREDENTIAL_SCOPE_METADATA[value],
  }));

const API_CREDENTIAL_SCOPE_SET = new Set<string>(API_CREDENTIAL_SCOPES);

export function isApiCredentialScope(value: string): value is ApiCredentialScope {
  return API_CREDENTIAL_SCOPE_SET.has(value);
}
