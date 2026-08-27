import { isApiCredentialScope } from '@seams-internal/wallet-console-shared/apiKeyScopes';
import type { ConsoleApiKeyService } from '@seams-internal/console-server/apiKeys/index';
import type {
  AuthenticateConsoleApiKeyResult,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
} from '@seams-internal/console-server/apiKeys/index';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing/index';
import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv/index';
import type { ConsoleWalletService } from '../wallets';
import type {
  RouterApiKeyAuthAdapter,
  RouterApiKeyAuthRequest,
  RouterApiKeyAuthResult,
  RouterApiKeyPrincipal,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiPublishableKeyAuthRequest,
  RouterApiPublishableKeyAuthResult,
  RouterApiUsageMeterAdapter,
  RouterApiUsageMeterEvent,
  RouterApiWalletProjectionAdapter,
  RouterApiWalletProjectionEvent,
} from '@seams/wallet-server/cloud-host';

function toPrincipal(apiKey: ConsoleApiKey): RouterApiKeyPrincipal {
  return {
    apiKeyId: apiKey.id,
    orgId: apiKey.orgId,
    environmentId: apiKey.environmentId,
    scopes: (apiKey.scopes || []).filter(isApiCredentialScope),
  };
}

function toRouterApiAuthResult(result: AuthenticateConsoleApiKeyResult): RouterApiKeyAuthResult {
  if (result.ok) {
    return {
      ok: true,
      principal: toPrincipal(result.apiKey),
    };
  }
  return result;
}

function toRouterApiPublishableAuthResult(
  result: AuthenticateConsolePublishableKeyResult,
): RouterApiPublishableKeyAuthResult {
  if (result.ok) {
    return {
      ok: true,
      principal: toPrincipal(result.apiKey),
    };
  }
  return result;
}

async function upsertProjectedWallet(input: {
  readonly wallets: ConsoleWalletService;
  readonly orgId: string;
  readonly actorUserId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly walletId: string;
  readonly occurredAt: string;
}): Promise<void> {
  if (!input.wallets.upsertWallet) {
    throw new Error('Console wallet projection is not configured');
  }
  await input.wallets.upsertWallet(
    {
      orgId: input.orgId,
      actorUserId: input.actorUserId,
      projectId: input.projectId,
      environmentId: input.environmentId,
    },
    {
      id: input.walletId,
      projectId: input.projectId,
      environmentId: input.environmentId,
      userId: input.walletId,
      externalRefId: input.walletId,
      address: input.walletId,
      chain: 'Multichain',
      walletType: 'EOA',
      status: 'ACTIVE',
      policyId: null,
      balanceMinor: 0,
      lastActivityAt: input.occurredAt,
      createdAt: input.occurredAt,
      updatedAt: input.occurredAt,
    },
  );
}

class ConsoleRouterApiKeyAuthAdapter implements RouterApiKeyAuthAdapter {
  private readonly authenticateApiKey: NonNullable<ConsoleApiKeyService['authenticateApiKey']>;

  constructor(apiKeys: ConsoleApiKeyService) {
    const authenticateApiKey = apiKeys.authenticateApiKey;
    if (typeof authenticateApiKey !== 'function') {
      throw new Error(
        'ConsoleApiKeyService.authenticateApiKey is required for Router API key auth',
      );
    }
    this.authenticateApiKey = authenticateApiKey.bind(apiKeys);
  }

  async authenticate(input: RouterApiKeyAuthRequest): Promise<RouterApiKeyAuthResult> {
    return toRouterApiAuthResult(await this.authenticateApiKey(input));
  }
}

class ConsoleRouterApiPublishableKeyAuthAdapter implements RouterApiPublishableKeyAuthAdapter {
  private readonly authenticatePublishableKey: NonNullable<
    ConsoleApiKeyService['authenticatePublishableKey']
  >;

  constructor(apiKeys: ConsoleApiKeyService) {
    const authenticatePublishableKey = apiKeys.authenticatePublishableKey;
    if (typeof authenticatePublishableKey !== 'function') {
      throw new Error(
        'ConsoleApiKeyService.authenticatePublishableKey is required for Router API publishable key auth',
      );
    }
    this.authenticatePublishableKey = authenticatePublishableKey.bind(apiKeys);
  }

  async authenticate(
    input: RouterApiPublishableKeyAuthRequest,
  ): Promise<RouterApiPublishableKeyAuthResult> {
    return toRouterApiPublishableAuthResult(
      await this.authenticatePublishableKey({
        secret: input.secret,
        origin: input.origin,
        environmentId: input.environmentId,
      }),
    );
  }
}

class ConsoleRouterApiBillingUsageMeterAdapter implements RouterApiUsageMeterAdapter {
  constructor(
    private readonly billing: ConsoleBillingService,
    private readonly options: {
      orgProjectEnv?: ConsoleOrgProjectEnvService | null;
      wallets?: ConsoleWalletService | null;
    },
  ) {}

  async recordEvent(input: RouterApiUsageMeterEvent): Promise<void> {
    await this.billing.recordUsageEvent(
      {
        orgId: input.orgId,
        actorUserId: 'relay-api-key',
      },
      {
        resourceId: input.walletId,
        shouldCount: input.action !== 'wallet_created' && input.succeeded,
        ...(input.occurredAt ? { occurredAt: input.occurredAt } : {}),
        ...(input.sourceEventId ? { sourceEventId: input.sourceEventId } : {}),
      },
    );
    if (input.action === 'wallet_created' && input.succeeded) {
      await this.recordWalletProjection(input);
    }
  }

  private async recordWalletProjection(input: RouterApiUsageMeterEvent): Promise<void> {
    const orgProjectEnv = this.options.orgProjectEnv || null;
    const walletService = this.options.wallets || null;
    if (!orgProjectEnv || !walletService?.upsertWallet) return;
    const envs = await orgProjectEnv.listEnvironments({
      orgId: input.orgId,
      actorUserId: 'relay-api-key',
      environmentId: input.environmentId,
    });
    const environment = envs.find((entry) => entry.id === input.environmentId) || null;
    if (!environment) return;
    const nowIso = String(input.occurredAt || '').trim() || new Date().toISOString();
    await upsertProjectedWallet({
      wallets: walletService,
      orgId: input.orgId,
      actorUserId: 'relay-api-key',
      projectId: environment.projectId,
      environmentId: environment.id,
      walletId: input.walletId,
      occurredAt: nowIso,
    });
  }
}

class ConsoleRouterApiWalletProjectionAdapter implements RouterApiWalletProjectionAdapter {
  constructor(
    private readonly orgProjectEnv: ConsoleOrgProjectEnvService,
    private readonly wallets: ConsoleWalletService,
  ) {}

  async recordCreatedWallet(input: RouterApiWalletProjectionEvent): Promise<void> {
    const environments = await this.orgProjectEnv.listEnvironments({
      orgId: input.orgId,
      actorUserId: 'wallet-registration-projection',
      projectId: input.runtimePolicyScope.projectId,
    });
    const environment = environments.find(
      (entry) =>
        entry.projectId === input.runtimePolicyScope.projectId &&
        entry.key === input.runtimePolicyScope.envId,
    );
    if (!environment) {
      throw new Error(
        `Wallet projection environment ${input.runtimePolicyScope.projectId}:${input.runtimePolicyScope.envId} was not found`,
      );
    }
    await upsertProjectedWallet({
      wallets: this.wallets,
      orgId: input.orgId,
      actorUserId: 'wallet-registration-projection',
      projectId: environment.projectId,
      environmentId: environment.id,
      walletId: input.walletId,
      occurredAt: input.occurredAt,
    });
  }
}

export function createRouterApiKeyAuthAdapter(
  apiKeys: ConsoleApiKeyService,
): RouterApiKeyAuthAdapter {
  return new ConsoleRouterApiKeyAuthAdapter(apiKeys);
}

export function createRouterApiPublishableKeyAuthAdapter(
  apiKeys: ConsoleApiKeyService,
): RouterApiPublishableKeyAuthAdapter {
  return new ConsoleRouterApiPublishableKeyAuthAdapter(apiKeys);
}

export function createRouterApiBillingUsageMeterAdapter(
  billing: ConsoleBillingService,
  options: {
    orgProjectEnv?: ConsoleOrgProjectEnvService | null;
    wallets?: ConsoleWalletService | null;
  } = {},
): RouterApiUsageMeterAdapter {
  return new ConsoleRouterApiBillingUsageMeterAdapter(billing, options);
}

export function createRouterApiWalletProjectionAdapter(
  orgProjectEnv: ConsoleOrgProjectEnvService,
  wallets: ConsoleWalletService,
): RouterApiWalletProjectionAdapter {
  return new ConsoleRouterApiWalletProjectionAdapter(orgProjectEnv, wallets);
}
