import { UserVerificationPolicy, type AuthenticatorOptions } from '../types/authenticatorOptions';
import type { RegistrationSignerOptions } from '../types/registrationSignerOptions';
import type {
  TatchiChainConfig,
  TatchiConfigsInput,
  TatchiConfigsReadonly,
  ThresholdEcdsaPresignPoolPolicy,
} from '../types/tatchi';
import { buildConfigsFromDefaults } from './configBuilder';

// Default SDK configs suitable for local dev.
// Cross-origin wallet isolation is recommended; set `iframeWallet.walletOrigin` in your app config when you have a dedicated origin.
// Consumers can shallow-merge overrides by field.

export const DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY: ThresholdEcdsaPresignPoolPolicy = {
  enabled: true,
  targetDepth: 3,
  lowWatermark: 1,
  maxRefillInFlight: 1,
  refillAttemptTimeoutMs: 30_000,
};

export const DEFAULT_CHAIN_CONFIGS: TatchiChainConfig[] = [
  {
    network: 'near-testnet',
    // You can provide a single URL or a comma-separated list for failover.
    // First URL is treated as primary, subsequent URLs are fallbacks.
    rpcUrl: 'https://test.rpc.fastnear.com, https://rpc.testnet.near.org',
    explorerUrl: 'https://testnet.nearblocks.io',
  },
  {
    network: 'tempo-testnet',
    rpcUrl: 'https://rpc.moderato.tempo.xyz',
    explorerUrl: 'https://explore.tempo.xyz',
    chainId: 42431,
  },
  {
    network: 'arc-testnet',
    rpcUrl: 'https://rpc.testnet.arc.network',
    explorerUrl: 'https://testnet.arcscan.app',
    chainId: 5042002,
  },
  {
    network: 'ethereum-sepolia',
    rpcUrl: 'https://ethereum-sepolia-rpc.publicnode.com',
    explorerUrl: 'https://sepolia.etherscan.io',
    chainId: 11155111,
  },
];

export const PASSKEY_MANAGER_DEFAULT_CONFIGS: TatchiConfigsReadonly = {
  network: {
    chains: DEFAULT_CHAIN_CONFIGS,
    relayer: {
      accountId: 'w3a-relayer.testnet',
      // No default relayer URL. Force apps to configure via env/overrides.
      // Using an empty string triggers early validation errors in code paths that require it.
      url: '',
      routes: {
        delegateAction: '/signed-delegate',
        smartAccountDeploy: '/smart-account/deploy',
      },
      smartAccountDeployment: {
        mode: 'enforce',
        maxAttempts: 2,
      },
      emailRecovery: {
        // Require at least 0.01 NEAR available to start email recovery.
        minBalanceYocto: '10000000000000000000000', // 0.01 NEAR
        // Poll every 4 seconds for verification status / access key.
        pollingIntervalMs: 4000,
        // Stop polling after 30 minutes.
        maxPollingDurationMs: 30 * 60 * 1000,
        // Expire pending recovery records after 30 minutes.
        pendingTtlMs: 30 * 60 * 1000,
        // Default recovery mailbox for examples / docs.
        mailtoAddress: 'recover@web3authn.org',
        emailDkimVerifierContract: 'email-dkim-verifier-v1.testnet',
      },
    },
  },
  signing: {
    mode: { mode: 'threshold-signer' },
    // Warm signing session defaults used by login/unlock flows.
    // Enforcement (TTL/uses) is owned by the UserConfirm worker (wallet origin); signer workers remain one-shot.
    sessionDefaults: {
      ttlMs: 24 * 60 * 60 * 1000, // 1 day
      remainingUses: 10_000,
    },
    sessionPersistenceMode: 'none',
    sessionSeal: {},
    thresholdEcdsa: {
      presignPool: DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY,
    },
    registrationDefaults: {
      tempo: {
        enabled: true,
        participantIds: [1, 2],
        sessionKind: 'jwt',
        ttlMs: 24 * 60 * 60 * 1000,
        remainingUses: 10_000,
      },
      evm: {
        enabled: true,
        participantIds: [1, 2],
        sessionKind: 'jwt',
        ttlMs: 24 * 60 * 60 * 1000,
        remainingUses: 10_000,
      },
    } as RegistrationSignerOptions
  },
  // Configure iframeWallet in application code to point at your dedicated wallet origin when available.
  wallet: {
    mode: 'direct',
    iframe: {
      origin: 'https://wallet.example.localhost',
      servicePath: '/wallet-service',
      sdkBasePath: '/sdk',
      rpIdOverride: 'example.localhost',
    },
  },
  webauthn: {
    authenticatorOptions: {
      userVerification: UserVerificationPolicy.Preferred,
      originPolicy: {
        single: undefined,
        all_subdomains: true,
        multiple: undefined,
      },
    } as AuthenticatorOptions
  },
  ui: {
    appearance: {
      theme: 'dark',
      palette: 'default',
      tokens: {
        light: { colors: {} },
        dark: { colors: {} },
      },
    },
  },
};

// Default threshold participant identifiers (2P FROST).
// These are intentionally exported as standalone constants so apps can reuse them when wiring
// threshold signing across client + server environments.
export const THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID = 1 as const;
export const THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID = 2 as const;
export const THRESHOLD_ED25519_2P_PARTICIPANT_IDS = [
  THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID,
  THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID,
] as const;

export function buildConfigsFromEnv(overrides: TatchiConfigsInput = {}): TatchiConfigsReadonly {
  return buildConfigsFromDefaults({
    defaults: PASSKEY_MANAGER_DEFAULT_CONFIGS,
    overrides,
    fallbackThresholdEcdsaPresignPoolPolicy: DEFAULT_THRESHOLD_ECDSA_PRESIGN_POOL_POLICY,
  });
}
