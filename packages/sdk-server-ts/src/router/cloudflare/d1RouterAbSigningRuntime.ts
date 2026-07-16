import {
  createCloudflareDurableObjectRouterAbSigningRuntimes,
  type CloudflareDurableObjectRouterAbSigningAuthPort,
} from '../../core/routerAbSigning/createCloudflareDurableObjectRouterAbSigningRuntimes';
import type { RouterAbSigningRuntimeBundle } from '../../core/routerAbSigning/createRouterAbSigningRuntimes';
import type { RouterAbNormalSigningRuntime } from '../../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { RouterAbLocalSigningSeedRuntime } from '../../core/routerAbSigning/RouterAbLocalSigningSeedRuntime';
import type { RouterAbEcdsaBootstrapExportPort } from '../../core/routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
import type { RouterAbEcdsaPresignRuntime } from '../../core/routerAbSigning/RouterAbEcdsaPresignRuntime';
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
type EcdsaDerivationRoleLocalBootstrapInput = Parameters<
  RouterApiThresholdRuntimeService['ecdsaDerivationRoleLocalBootstrap']
>[0];
type EcdsaDerivationRoleLocalBootstrapResult = Awaited<
  ReturnType<RouterApiThresholdRuntimeService['ecdsaDerivationRoleLocalBootstrap']>
>;
type VerifyEcdsaDerivationRoleLocalClientRootProofForExistingKeyInput = Parameters<
  RouterApiThresholdRuntimeService['verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey']
>[0];
type VerifyEcdsaDerivationRoleLocalClientRootProofForExistingKeyResult = Awaited<
  ReturnType<
    RouterApiThresholdRuntimeService['verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey']
  >
>;
type EcdsaDerivationRoleLocalExportShareInput = Parameters<
  RouterApiThresholdRuntimeService['ecdsaDerivationRoleLocalExportShare']
>[0];
type EcdsaDerivationRoleLocalExportShareResult = Awaited<
  ReturnType<RouterApiThresholdRuntimeService['ecdsaDerivationRoleLocalExportShare']>
>;

type CloudflareD1RouterAbSigningRuntimeOptions = {
  readonly relayerAccount?: string | null;
  readonly relayerPublicKey?: string | null;
  readonly routerAbSigningRuntimes?: RouterAbSigningRuntimeBundle | null;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly auth: Pick<
    CloudflareDurableObjectRouterAbSigningAuthPort,
    'verifyWebAuthnAuthenticationLite'
  >;
};

type CloudflareD1RouterAbSigningRuntimeState =
  | { readonly kind: 'uninitialized'; readonly runtimes?: never }
  | { readonly kind: 'unconfigured'; readonly runtimes?: never }
  | { readonly kind: 'ready'; readonly runtimes: RouterAbSigningRuntimeBundle };

export class CloudflareD1RouterAbSigningRuntime {
  private state: CloudflareD1RouterAbSigningRuntimeState = { kind: 'uninitialized' };

  constructor(private readonly options: CloudflareD1RouterAbSigningRuntimeOptions) {}

  getRouterAbNormalSigningRuntime(): RouterAbNormalSigningRuntime | null {
    const state = this.getRuntimeState();
    return state.kind === 'ready' ? state.runtimes.normalSigning : null;
  }

  getRouterAbLocalSigningSeedRuntime(): RouterAbLocalSigningSeedRuntime | null {
    const state = this.getRuntimeState();
    return state.kind === 'ready' ? state.runtimes.localSigningSeed : null;
  }

  getRouterAbEcdsaBootstrapExportRuntime(): RouterAbEcdsaBootstrapExportPort | null {
    const state = this.getRuntimeState();
    if (state.kind !== 'ready') return null;
    return state.runtimes.ecdsaBootstrapExport.kind === 'configured'
      ? state.runtimes.ecdsaBootstrapExport.runtime
      : null;
  }

  getRouterAbEcdsaPresignRuntime(): RouterAbEcdsaPresignRuntime | null {
    const state = this.getRuntimeState();
    return state.kind === 'ready' ? state.runtimes.ecdsaPresign : null;
  }

  private getRuntimeState(): Exclude<
    CloudflareD1RouterAbSigningRuntimeState,
    { readonly kind: 'uninitialized' }
  > {
    if (this.state.kind === 'uninitialized') {
      if (this.options.routerAbSigningRuntimes !== undefined) {
        this.state = this.options.routerAbSigningRuntimes
          ? { kind: 'ready', runtimes: this.options.routerAbSigningRuntimes }
          : { kind: 'unconfigured' };
      } else if (!this.options.thresholdStore) {
        this.state = { kind: 'unconfigured' };
      } else {
        this.state = {
          kind: 'ready',
          runtimes: createCloudflareDurableObjectRouterAbSigningRuntimes({
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

  async ecdsaDerivationRoleLocalBootstrap(
    request: EcdsaDerivationRoleLocalBootstrapInput,
  ): Promise<EcdsaDerivationRoleLocalBootstrapResult> {
    const runtime = this.getRouterAbEcdsaBootstrapExportRuntime();
    if (!runtime) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await runtime.ecdsaDerivationRoleLocalBootstrap(request);
  }

  async verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey(
    request: VerifyEcdsaDerivationRoleLocalClientRootProofForExistingKeyInput,
  ): Promise<VerifyEcdsaDerivationRoleLocalClientRootProofForExistingKeyResult> {
    const runtime = this.getRouterAbEcdsaBootstrapExportRuntime();
    if (!runtime) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await runtime.verifyEcdsaDerivationRoleLocalClientRootProofForExistingKey(request);
  }

  async ecdsaDerivationRoleLocalExportShare(
    input: EcdsaDerivationRoleLocalExportShareInput,
  ): Promise<EcdsaDerivationRoleLocalExportShareResult> {
    const runtime = this.getRouterAbEcdsaBootstrapExportRuntime();
    if (!runtime) {
      return {
        ok: false,
        code: 'internal',
        message: 'Threshold signing service is not configured',
      };
    }
    return await runtime.ecdsaDerivationRoleLocalExportShare(input);
  }
}

async function unsupportedCloudflareD1NearTransactionDispatch(): Promise<never> {
  throw new Error(
    'Cloudflare D1 Router API auth service does not support NEAR transaction dispatch',
  );
}
