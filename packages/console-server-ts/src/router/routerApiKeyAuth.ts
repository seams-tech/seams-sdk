import type { ConsoleApiKeyService } from '../apiKeys';
import type {
  AuthenticateConsoleApiKeyResult,
  AuthenticateConsolePublishableKeyResult,
  ConsoleApiKey,
} from '../apiKeys';
import type { ConsoleBillingService } from '../billing';
import type { ConsoleOrgProjectEnvService } from '../orgProjectEnv';
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
} from '@seams/sdk-server/internal/router/apiCredentialPorts';

function toPrincipal(apiKey: ConsoleApiKey): RouterApiKeyPrincipal {
  return {
    apiKeyId: apiKey.id,
    orgId: apiKey.orgId,
    environmentId: apiKey.environmentId,
    scopes: [...(apiKey.scopes || [])],
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

class ConsoleRouterApiKeyAuthAdapter implements RouterApiKeyAuthAdapter {
  private readonly authenticateApiKey: NonNullable<ConsoleApiKeyService['authenticateApiKey']>;

  constructor(apiKeys: ConsoleApiKeyService) {
    const authenticateApiKey = apiKeys.authenticateApiKey;
    if (typeof authenticateApiKey !== 'function') {
      throw new Error('ConsoleApiKeyService.authenticateApiKey is required for Router API key auth');
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
        roles: ['system'],
      },
      {
        walletId: input.walletId,
        action: input.action,
        succeeded: input.succeeded,
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
      roles: ['system'],
      environmentId: input.environmentId,
    });
    const environment = envs.find((entry) => entry.id === input.environmentId) || null;
    if (!environment) return;
    const nowIso = String(input.occurredAt || '').trim() || new Date().toISOString();
    await walletService.upsertWallet(
      {
        orgId: input.orgId,
        actorUserId: 'relay-api-key',
        roles: ['system'],
        projectId: environment.projectId,
        environmentId: environment.id,
      },
      {
        id: input.walletId,
        projectId: environment.projectId,
        environmentId: environment.id,
        userId: input.walletId,
        externalRefId: input.walletId,
        address: input.walletId,
        chain: 'NEAR',
        walletType: 'EOA',
        status: 'ACTIVE',
        policyId: null,
        balanceMinor: 0,
        lastActivityAt: nowIso,
        createdAt: nowIso,
        updatedAt: nowIso,
      },
    );
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
