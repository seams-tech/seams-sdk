import {
  createCloudflareDurableObjectThresholdSigningService,
  type CloudflareDurableObjectThresholdSigningAuthPort,
} from '../../core/ThresholdService/createCloudflareDurableObjectThresholdSigningService';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import type { ThresholdStoreConfigInput } from '../../core/types';
import type {
  RouterApiThresholdRuntimeService,
} from '../authServicePort';

const DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT = 'cloudflare-d1-relayer.local';
const DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY = 'd1-relayer-public-key';

type ListThresholdEcdsaKeyIdentityTargetsForUserInput =
  Parameters<RouterApiThresholdRuntimeService['listThresholdEcdsaKeyIdentityTargetsForUser']>[0];
type ListThresholdEcdsaKeyIdentityTargetsForUserResult =
  Awaited<
    ReturnType<RouterApiThresholdRuntimeService['listThresholdEcdsaKeyIdentityTargetsForUser']>
  >;
type ListWalletEcdsaKeyFactsInventoryInput =
  Parameters<RouterApiThresholdRuntimeService['listWalletEcdsaKeyFactsInventory']>[0];
type ListWalletEcdsaKeyFactsInventoryResult =
  Awaited<ReturnType<RouterApiThresholdRuntimeService['listWalletEcdsaKeyFactsInventory']>>;
type EcdsaHssRoleLocalBootstrapInput =
  Parameters<RouterApiThresholdRuntimeService['ecdsaHssRoleLocalBootstrap']>[0];
type EcdsaHssRoleLocalBootstrapResult =
  Awaited<ReturnType<RouterApiThresholdRuntimeService['ecdsaHssRoleLocalBootstrap']>>;
type VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyInput =
  Parameters<
    RouterApiThresholdRuntimeService['verifyEcdsaHssRoleLocalClientRootProofForExistingKey']
  >[0];
type VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyResult =
  Awaited<
    ReturnType<
      RouterApiThresholdRuntimeService['verifyEcdsaHssRoleLocalClientRootProofForExistingKey']
    >
  >;
type EcdsaHssRoleLocalExportShareInput =
  Parameters<RouterApiThresholdRuntimeService['ecdsaHssRoleLocalExportShare']>[0];
type EcdsaHssRoleLocalExportShareResult =
  Awaited<ReturnType<RouterApiThresholdRuntimeService['ecdsaHssRoleLocalExportShare']>>;

type CloudflareD1ThresholdSigningRuntimeOptions = {
  readonly relayerAccount?: string | null;
  readonly relayerPublicKey?: string | null;
  readonly thresholdSigningService?: ThresholdSigningService | null;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly auth: Pick<
    CloudflareDurableObjectThresholdSigningAuthPort,
    'verifyWebAuthnAuthenticationLite'
  >;
};

export class CloudflareD1ThresholdSigningRuntime {
  private thresholdSigningService: ThresholdSigningService | null = null;
  private initialized = false;

  constructor(private readonly options: CloudflareD1ThresholdSigningRuntimeOptions) {}

  getThresholdSigningService(): ThresholdSigningService | null {
    if (this.initialized) return this.thresholdSigningService;
    this.initialized = true;
    if (this.options.thresholdSigningService !== undefined) {
      this.thresholdSigningService = this.options.thresholdSigningService;
      return this.thresholdSigningService;
    }
    if (!this.options.thresholdStore) {
      this.thresholdSigningService = null;
      return null;
    }
    this.thresholdSigningService = createCloudflareDurableObjectThresholdSigningService({
      thresholdStore: this.options.thresholdStore,
      auth: {
        getRelayerAccount: this.getRelayerAccount.bind(this),
        verifyWebAuthnAuthenticationLite: this.options.auth.verifyWebAuthnAuthenticationLite,
        dispatchNearSignedTransactionBorsh: unsupportedCloudflareD1NearTransactionDispatch,
      },
    });
    return this.thresholdSigningService;
  }

  async listThresholdEcdsaKeyIdentityTargetsForUser(
    input: ListThresholdEcdsaKeyIdentityTargetsForUserInput,
  ): Promise<ListThresholdEcdsaKeyIdentityTargetsForUserResult> {
    const userId = optionalTrimmedString(input.userId);
    const rpId = optionalTrimmedString(input.rpId);
    const inputCount = input.keyTargets.length;
    if (!userId || !rpId) {
      return emptyThresholdEcdsaKeyInventoryResult({
        userId: userId || '',
        inputCount,
        rejectionReason: 'missing_scope',
      });
    }
    return emptyThresholdEcdsaKeyInventoryResult({
      userId,
      inputCount,
      rejectionReason: 'threshold_service_missing',
    });
  }

  async listWalletEcdsaKeyFactsInventory(
    input: ListWalletEcdsaKeyFactsInventoryInput,
  ): Promise<ListWalletEcdsaKeyFactsInventoryResult> {
    return await this.listThresholdEcdsaKeyIdentityTargetsForUser({
      userId: input.walletId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
    });
  }

  async getThresholdRelayerAccount(): Promise<{
    readonly accountId: string;
    readonly publicKey: string;
  }> {
    return {
      accountId: this.getConfiguredRelayerAccount(),
      publicKey: this.options.relayerPublicKey || DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY,
    };
  }

  getConfiguredRelayerAccount(): string {
    return this.options.relayerAccount || DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT;
  }

  async getRelayerAccount(): Promise<{
    readonly accountId: string;
    readonly publicKey: string;
  }> {
    return await this.getThresholdRelayerAccount();
  }

  async ecdsaHssRoleLocalBootstrap(
    request: EcdsaHssRoleLocalBootstrapInput,
  ): Promise<EcdsaHssRoleLocalBootstrapResult> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.ecdsaHssRoleLocalBootstrap(request);
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyInput,
  ): Promise<VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyResult> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.verifyEcdsaHssRoleLocalClientRootProofForExistingKey(request);
  }

  async ecdsaHssRoleLocalExportShare(
    input: EcdsaHssRoleLocalExportShareInput,
  ): Promise<EcdsaHssRoleLocalExportShareResult> {
    const threshold = this.getThresholdSigningService();
    if (!threshold) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await threshold.ecdsaHssRoleLocalExportShare(input);
  }
}

async function unsupportedCloudflareD1NearTransactionDispatch(): Promise<never> {
  throw new Error(
    'Cloudflare D1 Router API auth service does not support NEAR transaction dispatch',
  );
}

function optionalTrimmedString(input: unknown): string {
  return String(input || '').trim();
}

function singletonRejectedDiagnostic(reason: string): Record<string, number> {
  return { [reason]: 1 };
}

function emptyThresholdEcdsaKeyInventoryResult(input: {
  readonly userId: string;
  readonly inputCount: number;
  readonly rejectionReason: 'missing_scope' | 'threshold_service_missing';
}): ListThresholdEcdsaKeyIdentityTargetsForUserResult {
  return {
    records: [],
    diagnostics: {
      userId: input.userId,
      inputCount: input.inputCount,
      returnedCount: 0,
      thresholdServicePresent: false,
      rejected: singletonRejectedDiagnostic(input.rejectionReason),
    },
  };
}
