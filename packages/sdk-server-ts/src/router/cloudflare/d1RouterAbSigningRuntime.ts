import {
  createCloudflareDurableObjectRouterAbSigningRuntimes,
  type CloudflareDurableObjectRouterAbSigningAuthPort,
} from '../../core/routerAbSigning/createCloudflareDurableObjectRouterAbSigningRuntimes';
import type { RouterAbSigningRuntimeBundle } from '../../core/routerAbSigning/createRouterAbSigningRuntimes';
import type { RouterAbNormalSigningRuntime } from '../../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { RouterAbLocalSigningSeedRuntime } from '../../core/routerAbSigning/RouterAbLocalSigningSeedRuntime';
import type { RouterAbEcdsaPresignRuntime } from '../../core/routerAbSigning/RouterAbEcdsaPresignRuntime';
import type { ThresholdStoreConfigInput } from '../../core/types';

const DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT = 'cloudflare-d1-relayer.local';
const DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY = 'd1-relayer-public-key';

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

}

async function unsupportedCloudflareD1NearTransactionDispatch(): Promise<never> {
  throw new Error(
    'Cloudflare D1 Router API auth service does not support NEAR transaction dispatch',
  );
}
