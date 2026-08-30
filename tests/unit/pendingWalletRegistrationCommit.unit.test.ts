import { expect, test } from '@playwright/test';
import {
  parsePendingWalletRegistrationCommitStorageRow,
  parsePendingWalletRegistrationCommitV1,
  parsePendingWalletRegistrationCommitAppStateRow,
  toPendingWalletRegistrationCommitAppStateRow,
  toPendingWalletRegistrationCommitStorageRow,
} from '../../packages/wallet/src/core/indexedDB/pendingWalletRegistrationCommit';

const custodyCommit = {
  walletId: 'wallet_pending_registration',
  keySet: 'near_ed25519_v1',
  keyManifestDigestB64u: 'manifest-digest',
};

const activationReference = {
  kind: 'router_ab_ed25519_yao_activation_reference_v1',
  lifecycle_id: 'lifecycle-pending-registration',
  session_id: Array.from({ length: 32 }, (_, index) => index),
};

const ed25519LocalMaterial = {
  b64u: 'sealed-ed25519-material',
  nonceB64u: 'sealed-ed25519-nonce',
  applicationBindingDigestB64u: 'ed25519-binding',
};

const ed25519Metadata = {
  materialActivation: {
    kind: 'mpc_material_activation_ref',
    activationId: 'activation-pending',
    capability: 'capability-pending',
    materialOwner: 'material-owner-pending',
    keyBinding: 'key-binding-pending',
    lifecycleBinding: 'lifecycle-binding-pending',
    signingWorker: 'signing-worker-pending',
  },
  registeredPublicKeyB64u: 'registered-ed25519-public-key',
  signingWorkerVerifyingShareB64u: 'signing-worker-verifying-share',
  stateEpoch: '1',
  signingWorkerId: 'signing-worker-pending',
  participantIds: [1, 2],
  nearEd25519SigningKeyId: 'ed25519-key-pending',
  signerSlot: 1,
};

function pendingRecord(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'pending_wallet_registration_commit_v1',
    operation: 'registration_activate',
    registrationCeremonyId: 'registration-ceremony-pending',
    idempotencyKey: 'wallet-registration-finalize:pending',
    walletId: custodyCommit.walletId,
    walletAuthMethodId: 'wallet-auth-method:pending',
    signedSetup: 'signed-setup-pending',
    auth: {
      kind: 'passkey',
      rpId: 'example.com',
      credentialIdB64u: 'credential-pending',
      transports: ['internal'],
    },
    localMaterial: {
      keyFamilies: ['ed25519'],
      custodyCommit,
      ed25519: {
        activationReference,
        localMaterial: ed25519LocalMaterial,
        metadata: ed25519Metadata,
      },
    },
    createdAtMs: 100,
    updatedAtMs: 200,
    ...overrides,
  };
}

test('pending registration parser accepts activation and deferred NEAR records', () => {
  const activation = parsePendingWalletRegistrationCommitV1(pendingRecord());
  expect(activation).not.toBeNull();
  expect(activation?.operation).toBe('registration_activate');

  const nearProvisioning = parsePendingWalletRegistrationCommitV1(
    pendingRecord({
      operation: 'near_provisioning',
      idempotencyKey: 'wallet-registration-near-provisioning:pending',
    }),
  );
  expect(nearProvisioning).not.toBeNull();
  expect(nearProvisioning?.operation).toBe('near_provisioning');

  const email = parsePendingWalletRegistrationCommitV1(
    pendingRecord({
      auth: {
        kind: 'email_otp',
        email: 'pending@example.com',
        registrationAuthorityId: 'registration-authority-pending',
        providerSubject: 'provider-subject-pending',
        enrollment: {
          enrollmentSealKeyVersion: 'enrollment-key-v1',
          serverSealedFactorCiphertextB64u: 'sealed-factor-pending',
          clientUnlockPublicKeyB64u: 'unlock-public-key-pending',
          unlockKeyVersion: 'unlock-key-v1',
        },
      },
    }),
  );
  expect(email?.auth.kind).toBe('email_otp');

  const establishedCustody = parsePendingWalletRegistrationCommitV1(
    pendingRecord({
      localMaterial: {
        keyFamilies: ['ed25519'],
        custodyCommit: {
          ...custodyCommit,
          establishedCustody: {
            envelopeId: 'envelope-pending',
            envelopeBindingJson: '{}',
            envelopeNonceB64u: 'envelope-nonce',
            sealedCustodySecretB64u: 'sealed-custody-secret',
            envelopeAadHashB64u: 'envelope-aad',
            envelopeCiphertextDigestB64u: 'envelope-digest',
            recoveryManifestKekWraps: [
              {
                recoveryKeyId: 'recovery-key',
                nonceB64u: 'recovery-nonce',
                ciphertextB64u: 'recovery-ciphertext',
                aadHashB64u: 'recovery-aad',
              },
            ],
            recoveryEntryNonceB64u: 'entry-nonce',
            recoveryEntryCiphertextB64u: 'entry-ciphertext',
            recoveryEntryAadHashB64u: 'entry-aad',
          },
        },
        ed25519: {
          activationReference,
          localMaterial: ed25519LocalMaterial,
          metadata: ed25519Metadata,
        },
      },
    }),
  );
  expect(establishedCustody).not.toBeNull();
});

test('pending registration parser requires complete Ed25519 publication metadata', () => {
  expect(
    parsePendingWalletRegistrationCommitV1(
      pendingRecord({
        localMaterial: {
          keyFamilies: ['ed25519'],
          custodyCommit,
          ed25519: {
            activationReference,
            localMaterial: ed25519LocalMaterial,
          },
        },
      }),
    ),
  ).toBeNull();
  expect(
    parsePendingWalletRegistrationCommitV1(
      pendingRecord({
        localMaterial: {
          keyFamilies: ['ed25519'],
          custodyCommit,
          ed25519: {
            activationReference,
            localMaterial: ed25519LocalMaterial,
            metadata: { ...ed25519Metadata, participantIds: [1] },
          },
        },
      }),
    ),
  ).toBeNull();
});

test('pending registration parser keeps ECDSA and mixed local-material branches distinct', () => {
  const ecdsa = parsePendingWalletRegistrationCommitV1(
    pendingRecord({
      localMaterial: {
        keyFamilies: ['ecdsa_secp256k1'],
        custodyCommit: { ...custodyCommit, keySet: 'evm_family_ecdsa_v1' },
        ecdsa: {
          activationJournalId: 'ecdsa-activation-journal-pending',
        },
      },
    }),
  );
  expect(ecdsa?.localMaterial.keyFamilies).toEqual(['ecdsa_secp256k1']);

  const mixed = parsePendingWalletRegistrationCommitV1(
    pendingRecord({
      localMaterial: {
        keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
        custodyCommit: { ...custodyCommit, keySet: 'evm_family_ecdsa_v1' },
        ed25519: {
          activationReference,
          localMaterial: ed25519LocalMaterial,
          metadata: ed25519Metadata,
        },
        ecdsa: {
          activationJournalId: 'ecdsa-activation-journal-pending',
        },
      },
    }),
  );
  expect(mixed?.localMaterial.keyFamilies).toEqual(['ed25519', 'ecdsa_secp256k1']);
});

test('pending registration storage rows round-trip without exposing credentials', () => {
  const parsed = parsePendingWalletRegistrationCommitV1(pendingRecord());
  expect(parsed).not.toBeNull();
  if (!parsed) return;

  const row = toPendingWalletRegistrationCommitStorageRow(parsed);
  expect(row).toEqual({
    registration_ceremony_id: parsed.registrationCeremonyId,
    operation: parsed.operation,
    wallet_id: parsed.walletId,
    wallet_auth_method_id: parsed.walletAuthMethodId,
    updated_at_ms: parsed.updatedAtMs,
    record: parsed,
  });
  expect(JSON.stringify(row)).not.toMatch(/walletSessionToken|operationCredential|response/);
  expect(parsed.auth.kind === 'passkey' ? parsed.auth.transports : null).toEqual(['internal']);
  expect(parsePendingWalletRegistrationCommitStorageRow(row)).toEqual(row);

  const appStateRow = toPendingWalletRegistrationCommitAppStateRow(parsed);
  expect(appStateRow.key).toBe(
    `pending_wallet_registration_commit_v1:${parsed.registrationCeremonyId}:${parsed.operation}`,
  );
  expect(parsePendingWalletRegistrationCommitAppStateRow(appStateRow)).toEqual(row);
});

test('pending registration parser rejects credentials, responses, malformed timestamps, and extra row keys', () => {
  const forbiddenFields = [
    { walletSessionToken: 'wst:secret' },
    { operationCredential: { token: 'secret' } },
    { primaryOperationCredential: { token: 'secret' } },
    { childOperationCredential: { token: 'secret' } },
    { response: { walletId: custodyCommit.walletId } },
    {
      localMaterial: {
        keyFamilies: ['ed25519'],
        custodyCommit: { ...custodyCommit, establishedCustody: { walletSessionToken: 'secret' } },
        ed25519: {
          activationReference,
          localMaterial: ed25519LocalMaterial,
          metadata: ed25519Metadata,
        },
      },
    },
    {
      localMaterial: {
        keyFamilies: ['ecdsa_secp256k1'],
        custodyCommit,
        ecdsa: {
          activationJournalId: 'ecdsa-activation-journal-pending',
          publicFacts: {},
          readyStateBlobB64u: 'unencrypted-ready-state',
        },
      },
    },
  ];

  for (const forbidden of forbiddenFields) {
    expect(parsePendingWalletRegistrationCommitV1(pendingRecord(forbidden))).toBeNull();
  }
  expect(parsePendingWalletRegistrationCommitV1(pendingRecord({ createdAtMs: 0 }))).toBeNull();
  expect(
    parsePendingWalletRegistrationCommitV1(
      pendingRecord({
        auth: {
          kind: 'passkey',
          rpId: 'example.com',
          credentialIdB64u: 'credential-pending',
          transports: ['internal', 'internal'],
        },
      }),
    ),
  ).toBeNull();
  expect(
    parsePendingWalletRegistrationCommitV1(
      pendingRecord({
        localMaterial: {
          keyFamilies: ['ed25519'],
          custodyCommit: { ...custodyCommit, walletId: 'other-wallet' },
          ed25519: {
            activationReference,
            localMaterial: ed25519LocalMaterial,
            metadata: ed25519Metadata,
          },
        },
      }),
    ),
  ).toBeNull();
  expect(
    parsePendingWalletRegistrationCommitV1(
      pendingRecord({
        localMaterial: {
          keyFamilies: ['ecdsa_secp256k1'],
          custodyCommit,
          ecdsa: {
            activationJournalId: 'ecdsa-activation-journal-pending',
          },
        },
      }),
    ),
  ).toBeNull();

  const parsed = parsePendingWalletRegistrationCommitV1(pendingRecord());
  expect(parsed).not.toBeNull();
  if (!parsed) return;
  const row = toPendingWalletRegistrationCommitStorageRow(parsed);
  expect(
    parsePendingWalletRegistrationCommitStorageRow({ ...row, unexpected: 'legacy-response' }),
  ).toBeNull();
});
