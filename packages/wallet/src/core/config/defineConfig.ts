import type {
  SeamsChainConfigInput,
  SeamsChainNetwork,
  SeamsConfigsInput,
} from '@/core/types/seams';

/**
 * The four values a browser wallet cannot start without.
 *
 * Every field of `SeamsConfigsInput` is optional, because the wallet-host
 * runtime builds partial configs — which means `{} satisfies SeamsConfigsInput`
 * compiles and then throws at runtime. `defineSeamsConfig` is the application's
 * entry point, so it makes the real contract compile-time enforced.
 */
export type SeamsRequiredConfigInput = {
  /** Origin serving the wallet iframe, e.g. `https://wallet.example.com`. */
  walletOrigin: string;
  /** Router API base URL used to create NEAR accounts. */
  relayerUrl: string;
  /**
   * Managed-registration publishable key.
   *
   * This alone identifies the environment: the key's record carries the
   * environment it belongs to, and the server resolves the runtime policy scope
   * from the authenticated key.
   */
  publishableKey: string;
  /**
   * Optional cross-check. When supplied, a publishable key belonging to a
   * different environment is rejected instead of silently working — useful when
   * one build can be pointed at staging or production by configuration.
   */
  projectEnvironmentId?: string;
};

export type DefineSeamsConfigInput = SeamsRequiredConfigInput &
  Omit<SeamsConfigsInput, 'iframeWallet' | 'relayer' | 'registration'> & {
    /**
     * Chains to configure. Omitted, the SDK's defaults apply — which already
     * carry working testnet RPC and explorer URLs (and RPC failover for NEAR).
     */
    chains?: SeamsChainConfigInput[];
    /** Escape hatches for the fields the four required values normally cover. */
    iframeWallet?: Omit<NonNullable<SeamsConfigsInput['iframeWallet']>, 'walletOrigin'>;
    relayer?: Omit<NonNullable<SeamsConfigsInput['relayer']>, 'url'>;
    registration?: Omit<
      NonNullable<SeamsConfigsInput['registration']>,
      'projectEnvironmentId' | 'publishableKey'
    >;
  };

/**
 * Builds a `SeamsConfigsInput` from the values an application actually has to
 * supply. Everything else — wallet service path, SDK base path, relayer
 * account, chain RPC and explorer URLs — comes from the SDK defaults.
 *
 * @example
 * const config = defineSeamsConfig({
 *   walletOrigin: import.meta.env.VITE_WALLET_ORIGIN,
 *   relayerUrl: import.meta.env.VITE_RELAYER_URL,
 *   publishableKey: import.meta.env.VITE_SEAMS_PUBLISHABLE_KEY,
 * });
 */
export function defineSeamsConfig(input: DefineSeamsConfigInput): SeamsConfigsInput {
  const { walletOrigin, relayerUrl, projectEnvironmentId, publishableKey, ...rest } = input;
  return {
    ...rest,
    iframeWallet: { ...input.iframeWallet, walletOrigin },
    relayer: { ...input.relayer, url: relayerUrl },
    registration: {
      mode: 'managed',
      ...input.registration,
      ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
      publishableKey,
    },
  };
}

const TESTNET_NETWORKS = [
  'near-testnet',
  'tempo-testnet',
] as const satisfies readonly SeamsChainNetwork[];

/**
 * `defineSeamsConfig` pinned to the NEAR and Tempo testnets — the pair the
 * getting-started guide signs on. Pass `chains` to configure a different set.
 */
export function seamsTestnetConfig(input: DefineSeamsConfigInput): SeamsConfigsInput {
  return defineSeamsConfig({
    chains: TESTNET_NETWORKS.map((network) => ({ network })) as SeamsChainConfigInput[],
    ...input,
  });
}
