import { expect, test } from '@playwright/test';

import {
  normalizeSealedRecoveryRecord,
  type RawSigningSessionSealedStoreRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord';

const TEMPO_CHAIN_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const;

const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'root',
  envId: 'email-otp',
  signingRootVersion: 'v1',
} as const;

function emailOtpEcdsaSealedRecoveryRecord(
  overrides: Partial<RawSigningSessionSealedStoreRecord> = {},
): RawSigningSessionSealedStoreRecord {
  const now = Date.now();
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: 'email_otp',
    secretKind: 'signing_session_secret32',
    storeKey: 'email_otp:ecdsa:tempo:tsess-ecdsa',
    signingGrantId: 'wsess-ecdsa',
    thresholdSessionIds: {
      ecdsa: 'tsess-ecdsa',
    },
    sealedSecretB64u: 'sealed-secret',
    curve: 'ecdsa',
    walletId: 'alice.testnet',
    relayerUrl: 'https://relay.example',
    ecdsaRestore: {
      chainTarget: TEMPO_CHAIN_TARGET,
      source: 'email_otp',
      // Chain-agnostic 5-part slot id: wallet-key:evm-family:<walletId>:<signingRootId>:<signingRootVersion>
      evmFamilySigningKeySlotId: 'wallet-key:evm-family:alice.testnet:root%3Aemail-otp:v1',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      providerSubjectId: 'google:alice',
      emailHashHex: 'email-hash-alice',
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ecdsa',
      keyHandle: 'key-handle-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      relayerKeyId: 'relayer-key',
      participantIds: [1, 2],
      // Required since Router A/B: canonical ECDSA records carry the normal-signing scope.
      routerAbEcdsaDerivationNormalSigning: {
        kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
        scope: {
          wallet_key_id: 'wallet-key:evm-family:alice.testnet:root%3Aemail-otp:v1',
          wallet_id: 'alice.testnet',
          ecdsa_threshold_key_id: 'ecdsa-key',
          signing_root_id: 'root:email-otp',
          signing_root_version: 'v1',
          context: {
            application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
          },
          public_identity: {
            context_binding_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
            derivation_client_share_public_key33_b64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            server_public_key33_b64u: 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            threshold_public_key33_b64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            ethereum_address20_b64u: 'MzMzMzMzMzMzMzMzMzMzMzMzMzM',
            client_share_retry_counter: 0,
            server_share_retry_counter: 0,
          },
          signing_worker: {
            server_id: 'signing-worker-ecdsa',
            key_epoch: 'epoch-ecdsa',
            recipient_encryption_key:
              'x25519:1111111111111111111111111111111111111111111111111111111111111111',
          },
          activation_epoch: 'tsess-ecdsa',
        },
      },
    },
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    remainingUses: 3,
    updatedAtMs: now,
    ...overrides,
  };
}

test.describe('sealed recovery record strict normalization', () => {
  test('accepts canonical Email OTP ECDSA sealed recovery records', () => {
    const normalized = normalizeSealedRecoveryRecord(emailOtpEcdsaSealedRecoveryRecord());

    expect(normalized).toMatchObject({
      kind: 'accepted',
      record: {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        walletId: 'alice.testnet',
      },
    });
  });

  test('rejects top-level userId as stale sealed recovery identity', () => {
    const normalized = normalizeSealedRecoveryRecord(
      emailOtpEcdsaSealedRecoveryRecord({ userId: 'legacy-user-id' }),
    );

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'invalid_identity',
      },
    });
  });
});
