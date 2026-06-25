import type {
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealWalletBudgetStatus,
} from '@server/threshold/session/signingSessionSeal/signingSessionSeal.types';
import { base64UrlEncode } from '@shared/utils/encoders';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';

function b64u(bytes: number[]): string {
  return base64UrlEncode(Uint8Array.from(bytes));
}

export function buildEcdsaCurveCollisionBudgetStatusFixture(
  label: string,
  input: {
    claimExpiresAtMs?: number;
    walletRemainingUses?: number;
    walletCommittedRemainingUses?: number;
    walletReservedUses?: number;
    walletAvailableUses?: number;
  } = {},
) {
  const nowMs = Date.now();
  const walletRemainingUses = input.walletRemainingUses ?? 2;
  const walletCommittedRemainingUses = input.walletCommittedRemainingUses ?? walletRemainingUses + 3;
  const walletReservedUses = input.walletReservedUses ?? 3;
  const walletAvailableUses = input.walletAvailableUses ?? walletRemainingUses;
  const walletKeyId = `wallet-key-curve-collision-${label}`;
  const claims = {
    sub: `budget-curve-collision-${label}.testnet`,
    walletId: `budget-curve-collision-${label}.testnet`,
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    thresholdSessionId: `threshold-login-curve-collision-${label}`,
    signingGrantId: `wsess-curve-collision-${label}`,
    keyScope: 'evm-family',
    subjectId: `budget-curve-collision-${label}.testnet`,
    chainTarget: {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 5042002,
      networkSlug: 'arc-testnet',
    },
    ecdsaThresholdKeyId: `ecdsa-key-curve-collision-${label}`,
    keyHandle: `key-handle-curve-collision-${label}`,
    relayerKeyId: `ecdsa-relayer-key-curve-collision-${label}`,
    walletKeyId,
    thresholdExpiresAtMs: input.claimExpiresAtMs ?? nowMs + 60_000,
    participantIds: [1, 2],
    routerAbEcdsaHssNormalSigning: {
      kind: 'router_ab_ecdsa_hss_normal_signing_v1',
      scope: {
        wallet_key_id: walletKeyId,
        wallet_id: `budget-curve-collision-${label}.testnet`,
        ecdsa_threshold_key_id: `ecdsa-key-curve-collision-${label}`,
        signing_root_id: `signing-root-curve-collision-${label}`,
        signing_root_version: 'v1',
        context: {
          application_binding_digest_b64u: b64u(
            Array.from({ length: 32 }, (_, index) => index + 4),
          ),
        },
        public_identity: {
          context_binding_b64u: b64u(Array.from({ length: 32 }, (_, index) => index + 1)),
          client_public_key33_b64u: b64u([0x02, ...Array.from({ length: 32 }, () => 1)]),
          server_public_key33_b64u: b64u([0x03, ...Array.from({ length: 32 }, () => 2)]),
          threshold_public_key33_b64u: b64u([0x02, ...Array.from({ length: 32 }, () => 3)]),
          ethereum_address20_b64u: b64u(Array.from({ length: 20 }, () => 0x11)),
          client_share_retry_counter: 0,
          server_share_retry_counter: 0,
        },
        signing_worker: {
          server_id: `signing-worker-curve-collision-${label}`,
          key_epoch: `signing-worker-epoch-curve-collision-${label}`,
          recipient_encryption_key: `x25519:${'33'.repeat(32)}`,
        },
        activation_epoch: `threshold-login-curve-collision-${label}`,
      },
    },
  } as const;

  const baseStatus = (input: {
    curve: 'ecdsa' | 'ed25519';
    thresholdSessionId: string;
    relayerKeyId: string;
    remainingUses: number;
  }) => {
    const base = {
    thresholdSessionId: input.thresholdSessionId,
    userId: claims.walletId,
    expiresAtMs: nowMs + 60_000,
    remainingUses: input.remainingUses,
    relayerKeyId: input.relayerKeyId,
    participantIds: [...claims.participantIds],
    };
    switch (input.curve) {
      case 'ecdsa':
        return {
          ...base,
          curve: 'ecdsa' as const,
          walletKeyId,
        };
      case 'ed25519':
        return {
          ...base,
          curve: 'ed25519' as const,
          rpId: 'example.localhost',
        };
    }
  };
  const makeThresholdStatus = (input: {
    curve: 'ecdsa' | 'ed25519';
    thresholdSessionId: string;
    relayerKeyId: string;
    remainingUses: number;
  }): SigningSessionSealThresholdSessionStatus => ({
    kind: 'wallet_session',
    ...baseStatus(input),
  });
  const makeWalletBudgetStatus = (input: {
    thresholdSessionId: string;
    signingGrantId: string;
    relayerKeyId: string;
    remainingUses: number;
  }): SigningSessionSealWalletBudgetStatus => ({
    kind: 'wallet_budget',
    signingGrantId: input.signingGrantId,
    ...baseStatus({
      curve: 'ecdsa',
      thresholdSessionId: input.thresholdSessionId,
      relayerKeyId: input.relayerKeyId,
      remainingUses: input.remainingUses,
    }),
    committedRemainingUses: walletCommittedRemainingUses,
    reservedUses: walletReservedUses,
    availableUses: walletAvailableUses,
  });

  return {
    claims,
    wrongCurveStatus: makeThresholdStatus({
      curve: 'ed25519',
      thresholdSessionId: claims.thresholdSessionId,
      relayerKeyId: `ed25519-relayer-key-curve-collision-${label}`,
      remainingUses: 3,
    }),
    ecdsaStatus: makeThresholdStatus({
      curve: 'ecdsa',
      thresholdSessionId: claims.thresholdSessionId,
      relayerKeyId: claims.relayerKeyId,
      remainingUses: 3,
    }),
    walletBudgetStatus: makeWalletBudgetStatus({
      thresholdSessionId: claims.thresholdSessionId,
      signingGrantId: claims.signingGrantId,
      relayerKeyId: claims.relayerKeyId,
      remainingUses: walletRemainingUses,
    }),
  };
}
