import {
  createCloudflareDurableObjectThresholdSigningService,
  type CloudflareDurableObjectThresholdSigningAuthPort,
} from '../../core/ThresholdService/createCloudflareDurableObjectThresholdSigningService';
import type { ThresholdSigningRuntimeBundle } from '../../core/ThresholdService/createThresholdSigningService';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import type { RouterAbNormalSigningRuntime } from '../../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { RouterAbLocalSigningSeedRuntime } from '../../core/routerAbSigning/RouterAbLocalSigningSeedRuntime';
import type { RouterAbEcdsaBootstrapExportRuntime } from '../../core/routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
import type { ThresholdStoreConfigInput } from '../../core/types';
import type { RouterApiThresholdRuntimeService } from '../authServicePort';
import { listThresholdEcdsaKeyIdentityTargetsForUser as listThresholdEcdsaKeyIdentityTargetsForUserWithDeps } from '../../core/authService/thresholdEcdsaKeyInventory';

const DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT = 'cloudflare-d1-relayer.local';
const DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY = 'd1-relayer-public-key';

type ListThresholdEcdsaKeyIdentityTargetsForUserInput = Parameters<
  RouterApiThresholdRuntimeService['listThresholdEcdsaKeyIdentityTargetsForUser']
>[0];
type ListThresholdEcdsaKeyIdentityTargetsForUserResult = Awaited<
  ReturnType<RouterApiThresholdRuntimeService['listThresholdEcdsaKeyIdentityTargetsForUser']>
>;
type ListWalletEcdsaKeyFactsInventoryInput = Parameters<
  RouterApiThresholdRuntimeService['listWalletEcdsaKeyFactsInventory']
>[0];
type ListWalletEcdsaKeyFactsInventoryResult = Awaited<
  ReturnType<RouterApiThresholdRuntimeService['listWalletEcdsaKeyFactsInventory']>
>;
type EcdsaHssRoleLocalBootstrapInput = Parameters<
  RouterApiThresholdRuntimeService['ecdsaHssRoleLocalBootstrap']
>[0];
type EcdsaHssRoleLocalBootstrapResult = Awaited<
  ReturnType<RouterApiThresholdRuntimeService['ecdsaHssRoleLocalBootstrap']>
>;
type VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyInput = Parameters<
  RouterApiThresholdRuntimeService['verifyEcdsaHssRoleLocalClientRootProofForExistingKey']
>[0];
type VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyResult = Awaited<
  ReturnType<
    RouterApiThresholdRuntimeService['verifyEcdsaHssRoleLocalClientRootProofForExistingKey']
  >
>;
type EcdsaHssRoleLocalExportShareInput = Parameters<
  RouterApiThresholdRuntimeService['ecdsaHssRoleLocalExportShare']
>[0];
type EcdsaHssRoleLocalExportShareResult = Awaited<
  ReturnType<RouterApiThresholdRuntimeService['ecdsaHssRoleLocalExportShare']>
>;

type CloudflareD1ThresholdSigningRuntimeOptions = {
  readonly relayerAccount?: string | null;
  readonly relayerPublicKey?: string | null;
  readonly thresholdSigningRuntimes?: ThresholdSigningRuntimeBundle | null;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly auth: Pick<
    CloudflareDurableObjectThresholdSigningAuthPort,
    'verifyWebAuthnAuthenticationLite'
  >;
};

type CloudflareD1ThresholdSigningRuntimeState =
  | { readonly kind: 'uninitialized'; readonly runtimes?: never }
  | { readonly kind: 'unconfigured'; readonly runtimes?: never }
  | { readonly kind: 'ready'; readonly runtimes: ThresholdSigningRuntimeBundle };

export class CloudflareD1ThresholdSigningRuntime {
  private state: CloudflareD1ThresholdSigningRuntimeState = { kind: 'uninitialized' };

  constructor(private readonly options: CloudflareD1ThresholdSigningRuntimeOptions) {}

  getThresholdSigningService(): ThresholdSigningService | null {
    const state = this.getRuntimeState();
    return state.kind === 'ready' ? state.runtimes.thresholdSigningService : null;
  }

  getRouterAbNormalSigningRuntime(): RouterAbNormalSigningRuntime | null {
    const state = this.getRuntimeState();
    return state.kind === 'ready' ? state.runtimes.routerAbNormalSigningRuntime : null;
  }

  getRouterAbLocalSigningSeedRuntime(): RouterAbLocalSigningSeedRuntime | null {
    const state = this.getRuntimeState();
    return state.kind === 'ready' ? state.runtimes.routerAbLocalSigningSeedRuntime : null;
  }

  getRouterAbEcdsaBootstrapExportRuntime(): RouterAbEcdsaBootstrapExportRuntime | null {
    const state = this.getRuntimeState();
    if (state.kind !== 'ready') return null;
    return state.runtimes.routerAbEcdsaBootstrapExportRuntime.kind === 'configured'
      ? state.runtimes.routerAbEcdsaBootstrapExportRuntime.runtime
      : null;
  }

  private getRuntimeState(): Exclude<
    CloudflareD1ThresholdSigningRuntimeState,
    { readonly kind: 'uninitialized' }
  > {
    if (this.state.kind === 'uninitialized') {
      if (this.options.thresholdSigningRuntimes !== undefined) {
        this.state = this.options.thresholdSigningRuntimes
          ? { kind: 'ready', runtimes: this.options.thresholdSigningRuntimes }
          : { kind: 'unconfigured' };
      } else if (!this.options.thresholdStore) {
        this.state = { kind: 'unconfigured' };
      } else {
        this.state = {
          kind: 'ready',
          runtimes: createCloudflareDurableObjectThresholdSigningService({
            thresholdStore: this.options.thresholdStore,
            auth: {
              getRelayerAccount: this.getRelayerAccount.bind(this),
              verifyWebAuthnAuthenticationLite: this.options.auth.verifyWebAuthnAuthenticationLite,
              dispatchNearSignedTransactionBorsh: unsupportedCloudflareD1NearTransactionDispatch,
            },
          }),
        };
      }
    }
    return this.state;
  }

  async listThresholdEcdsaKeyIdentityTargetsForUser(
    input: ListThresholdEcdsaKeyIdentityTargetsForUserInput,
  ): Promise<ListThresholdEcdsaKeyIdentityTargetsForUserResult> {
    return await listThresholdEcdsaKeyIdentityTargetsForUserWithDeps({
      userId: input.userId,
      rpId: input.rpId,
      keyTargets: input.keyTargets,
      ecdsaBootstrapExportRuntime: this.getRouterAbEcdsaBootstrapExportRuntime(),
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
    const runtime = this.getRouterAbEcdsaBootstrapExportRuntime();
    if (!runtime) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await runtime.ecdsaHssRoleLocalBootstrap(request);
  }

  async verifyEcdsaHssRoleLocalClientRootProofForExistingKey(
    request: VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyInput,
  ): Promise<VerifyEcdsaHssRoleLocalClientRootProofForExistingKeyResult> {
    const runtime = this.getRouterAbEcdsaBootstrapExportRuntime();
    if (!runtime) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await runtime.verifyEcdsaHssRoleLocalClientRootProofForExistingKey(request);
  }

  async ecdsaHssRoleLocalExportShare(
    input: EcdsaHssRoleLocalExportShareInput,
  ): Promise<EcdsaHssRoleLocalExportShareResult> {
    const runtime = this.getRouterAbEcdsaBootstrapExportRuntime();
    if (!runtime) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await runtime.ecdsaHssRoleLocalExportShare(input);
  }
}

async function unsupportedCloudflareD1NearTransactionDispatch(): Promise<never> {
  throw new Error(
    'Cloudflare D1 Router API auth service does not support NEAR transaction dispatch',
  );
}
