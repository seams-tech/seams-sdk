import type { TenantRootIdentityV1 } from '../tenantRootCreation/types';
import type { ApiCredentialScope } from '@seams-internal/wallet-console-shared/apiKeyScopes';

// The exact private service-binding surface between the Wallet Gateway and
// the Wallet Console deployment (R105 Phase 4). Five operations cross the
// binding: API-key validation, publishable-key validation, idempotent
// usage-event ingestion, project-environment lookup, and active tenant-root
// lineage lookup. There is no generic SQL or query operation, and the Gateway
// never receives the Console database.

export const WALLET_CONSOLE_OPS_BASE_PATH_V1 = '/internal/wallet-console/v1';
export const WALLET_CONSOLE_SERVICE_ORIGIN_V1 = 'https://wallet-console.internal';

export const WALLET_CONSOLE_OP_PATHS_V1 = {
  secretKeyAuth: `${WALLET_CONSOLE_OPS_BASE_PATH_V1}/secret-key-auth`,
  publishableKeyAuth: `${WALLET_CONSOLE_OPS_BASE_PATH_V1}/publishable-key-auth`,
  usageEvents: `${WALLET_CONSOLE_OPS_BASE_PATH_V1}/usage-events`,
  projectEnvironments: `${WALLET_CONSOLE_OPS_BASE_PATH_V1}/project-environments`,
  tenantRootActiveLineage: `${WALLET_CONSOLE_OPS_BASE_PATH_V1}/tenant-root/active-lineage`,
} as const;

export interface WalletConsoleSecretKeyAuthRequestV1 {
  readonly secret: string;
  readonly endpoint: string;
  readonly requiredScopes: ApiCredentialScope[];
  readonly sourceIp?: string;
  readonly environmentId?: string;
}

export interface WalletConsolePrincipalV1 {
  readonly apiKeyId: string;
  readonly orgId: string;
  readonly projectId?: string;
  readonly envId?: string;
  readonly environmentId: string;
  readonly scopes: readonly ApiCredentialScope[];
}

export type WalletConsoleSecretKeyAuthResponseV1 =
  | { readonly ok: true; readonly principal: WalletConsolePrincipalV1 }
  | {
      readonly ok: false;
      readonly status: 401 | 403;
      readonly code: string;
      readonly message: string;
    };

export interface WalletConsolePublishableKeyAuthRequestV1 {
  readonly secret: string;
  readonly origin: string;
  readonly environmentId: string;
}

export type WalletConsolePublishableKeyAuthResponseV1 = WalletConsoleSecretKeyAuthResponseV1;

export interface WalletConsoleUsageEventV1 {
  readonly orgId: string;
  readonly environmentId: string;
  readonly apiKeyId: string;
  readonly endpoint: string;
  readonly walletId: string;
  readonly action: 'wallet_created';
  readonly succeeded: boolean;
  readonly occurredAt?: string;
  /** Producer-owned idempotency key; replays with the same id must not double-count. */
  readonly sourceEventId?: string;
}

export interface WalletConsoleUsageEventsResponseV1 {
  readonly ok: boolean;
  readonly code?: string;
  readonly message?: string;
}

/**
 * Custody-sensitive commands the Console sends to the Wallet runtime. The
 * Console never receives signer custody storage; each command crosses the
 * private binding to the Wallet Runtime, which performs the custody work
 * inside its own trust boundary. Key-export authorization is the first exact
 * command; new commands are added here, never as generic passthroughs.
 */
export interface WalletControlPort {
  authorizeKeyExport(input: {
    readonly orgId: string;
    readonly environmentId: string;
    readonly walletId: string;
    readonly keyExportId: string;
    readonly approvedBy: string;
  }): Promise<
    { readonly ok: true } | { readonly ok: false; readonly code: string; readonly message: string }
  >;
}

export interface WalletConsoleProjectEnvironmentsRequestV1 {
  readonly context: {
    readonly orgId: string;
    readonly actorUserId: string;
    readonly roles: readonly string[];
    readonly environmentId?: string;
    readonly projectId?: string;
  };
  readonly filters?: { readonly status?: string };
}

export interface WalletConsoleProjectEnvironmentV1 {
  readonly id: string;
  readonly projectId: string;
  readonly key: string;
  readonly signingRootVersion: string;
  readonly status?: string;
}

export interface WalletConsoleProjectEnvironmentsResponseV1 {
  readonly ok: boolean;
  readonly environments?: readonly WalletConsoleProjectEnvironmentV1[];
  readonly code?: string;
  readonly message?: string;
}

export type WalletConsoleTenantRootActiveLineageRequestV1 = TenantRootIdentityV1;

export interface WalletConsoleTenantRootActiveLineageV1 {
  readonly identityDigestB64u: string;
  readonly custodyLineageB64u: string;
}

export interface WalletConsoleTenantRootActiveLineageResolverV1 {
  resolveActiveLineage(
    identity: WalletConsoleTenantRootActiveLineageRequestV1,
  ): Promise<WalletConsoleTenantRootActiveLineageV1 | null>;
}
