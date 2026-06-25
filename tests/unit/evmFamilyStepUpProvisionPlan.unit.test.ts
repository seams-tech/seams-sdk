import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type ThresholdEcdsaSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import {
  resolveReadyEvmFamilyEcdsaMaterial,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyPasskeyEcdsaProvisionPlan,
  buildEvmFamilyWarmSessionReconnectPlan,
} from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/provisionPlan';
import { ensureWarmEcdsaCapabilityReady } from '../../packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession';
import { SigningAuthPlanKind } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated,
} from '../../packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession';
import type { WarmSessionEcdsaCapabilityState } from '../../packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types';
import { selectedEcdsaLane } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import { buildThresholdEcdsaSecp256k1KeyRefFromRecord } from '../../packages/sdk-web/src/core/signingEngine/session/identity/thresholdEcdsaSignerAdapter';

const CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};
const TEST_PRF_FIRST_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_SHARE32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_GROUP_PUBLIC_KEY_B64U = 'AgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB';
const VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const TEST_WEBAUTHN_CREDENTIAL = {
  id: 'credential-id',
  rawId: 'raw-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: TEST_PRF_FIRST_B64U,
        second: undefined,
      },
    },
  },
} satisfies WebAuthnAuthenticationCredential;
const THRESHOLD_OWNER_ADDRESS = `0x${'11'.repeat(20)}` as const;
const TEST_PASSKEY_CREDENTIAL_ID_B64U = TEST_WEBAUTHN_CREDENTIAL.rawId;
const WALLET_KEY_ID = 'wallet-key-step-up-provision';
const PASSKEY_AUTH = {
  kind: 'passkey',
  rpId: toRpId('example.localhost'),
  credentialIdB64u: TEST_PASSKEY_CREDENTIAL_ID_B64U,
} as const;

function makeWalletSessionJwt(args: {
  thresholdSessionId: string;
  signingGrantId: string;
}): string {
  const encode = (value: object): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
    kind: 'router_ab_ecdsa_hss_wallet_session_v1',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    exp: 1_900_000_000,
  })}.signature`;
}

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function makeRouterAbEcdsaHssNormalSigningState(args: {
  record: Pick<
    ThresholdEcdsaSessionRecord,
    | 'walletId'
    | 'authMetadata'
    | 'ecdsaThresholdKeyId'
    | 'signingRootId'
    | 'signingRootVersion'
    | 'clientVerifyingShareB64u'
    | 'thresholdEcdsaPublicKeyB64u'
    | 'ethereumAddress'
    | 'thresholdSessionId'
  >;
}) {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: WALLET_KEY_ID,
      wallet_id: String(args.record.walletId),
      ecdsa_threshold_key_id: String(args.record.ecdsaThresholdKeyId),
      signing_root_id: String(args.record.signingRootId),
      signing_root_version: String(args.record.signingRootVersion),
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: VALID_ECDSA_SHARE32_B64U,
        client_public_key33_b64u: String(args.record.clientVerifyingShareB64u),
        server_public_key33_b64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: String(args.record.thresholdEcdsaPublicKeyB64u),
        ethereum_address20_b64u: ethereumAddress20B64u(String(args.record.ethereumAddress)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-step-up-fixture',
        key_epoch: 'worker-epoch-step-up-fixture',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: args.record.thresholdSessionId,
    },
  } as const;
}

function makeRecord(): ThresholdEcdsaSessionRecord {
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-step-up');
  const record: ThresholdEcdsaSessionRecord = {
    walletId: toWalletId('alice.testnet'),
    authMetadata: { walletKeyId: 'example.localhost' },
    chainTarget: CHAIN_TARGET,
    relayerUrl: 'https://relayer.test',
    keyHandle,
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'project:env',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
    ecdsaRoleLocalReadyRecord: buildEcdsaRoleLocalReadyRecord({
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: VALID_ECDSA_SHARE32_B64U,
      },
      publicFacts: buildEcdsaRoleLocalPublicFacts({
        walletId: toWalletId('alice.testnet'),
        walletKeyId: WALLET_KEY_ID,
        chainTarget: CHAIN_TARGET,
        keyHandle,
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        signingRootId: 'project:env',
        signingRootVersion: 'default',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        applicationBindingDigestB64u: VALID_ECDSA_SHARE32_B64U,
        contextBinding32B64u: VALID_ECDSA_SHARE32_B64U,
        hssClientSharePublicKey33B64u: VALID_ECDSA_CLIENT_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        groupPublicKey33B64u: VALID_ECDSA_GROUP_PUBLIC_KEY_B64U,
        ethereumAddress: THRESHOLD_OWNER_ADDRESS,
      }),
      authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: TEST_PASSKEY_CREDENTIAL_ID_B64U,
        rpId: 'example.localhost',
      }),
    }),
    participantIds: [1, 2],
    ethereumAddress: THRESHOLD_OWNER_ADDRESS,
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_GROUP_PUBLIC_KEY_B64U,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'wallet-session-1',
    runtimePolicyScope: {
      orgId: 'org-test',
      projectId: 'project',
      envId: 'env',
      signingRootVersion: 'default',
    },
    walletSessionJwt: makeWalletSessionJwt({
      thresholdSessionId: 'threshold-session-1',
      signingGrantId: 'wallet-session-1',
    }),
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 2,
    updatedAtMs: 1_800_000_000_000,
    source: 'login',
  };
  record.routerAbEcdsaHssNormalSigning = makeRouterAbEcdsaHssNormalSigningState({ record });
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record);
  return record;
}

function makeRecordWithIdentity(args: {
  thresholdSessionId: string;
  signingGrantId: string;
}): ThresholdEcdsaSessionRecord {
  const record: ThresholdEcdsaSessionRecord = {
    ...makeRecord(),
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: makeWalletSessionJwt(args),
  };
  record.routerAbEcdsaHssNormalSigning = makeRouterAbEcdsaHssNormalSigningState({ record });
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record);
  return record;
}

function requireWalletSessionJwt(record: ThresholdEcdsaSessionRecord): string {
  if (!record.walletSessionJwt) {
    throw new Error('expected ECDSA test record to include walletSessionJwt');
  }
  return record.walletSessionJwt;
}

function makeReadyMaterial(args: {
  record: ThresholdEcdsaSessionRecord;
  authMethod: 'passkey' | 'email_otp';
  source: 'login' | 'email_otp';
}): ReadyEvmFamilyEcdsaMaterial {
  const material = resolveReadyEvmFamilyEcdsaMaterial({
    record: args.record,
    expected: {
      walletId: args.record.walletId,
      walletKeyId: WALLET_KEY_ID,
      chainTarget: CHAIN_TARGET,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: args.record.thresholdSessionId,
      signingGrantId: args.record.signingGrantId,
    },
  });
  if (material.kind !== 'ready') {
    const persistedState = classifyRouterAbEcdsaHssPersistedSigningRecord(args.record);
    throw new Error(
      `expected ready EVM-family ECDSA material: ${material.kind}:${JSON.stringify(material.reason)} persisted=${JSON.stringify({
        kind: persistedState.kind,
        reason: 'reason' in persistedState ? persistedState.reason : undefined,
      })}`,
    );
  }
  return material.material;
}

function makeReadyEcdsaCapability(args: {
  record: ThresholdEcdsaSessionRecord;
  material: ReadyEvmFamilyEcdsaMaterial;
}): WarmSessionEcdsaCapabilityState {
  return {
    capability: 'ecdsa',
    record: args.record,
    key: args.material.key,
    lane: selectedEcdsaLane({
      key: args.material.key,
      keyHandle: args.record.keyHandle,
      walletId: args.record.walletId,
      auth: PASSKEY_AUTH,
      signingGrantId: args.record.signingGrantId,
      thresholdSessionId: args.record.thresholdSessionId,
      chainTarget: args.record.chainTarget,
    }),
    auth: {
      capability: 'ecdsa',
      state: 'ready',
      record: args.record,
      walletSessionJwt: requireWalletSessionJwt(args.record),
      walletSessionJwtSource: 'ecdsa_record',
    },
    prfClaim: {
      state: 'warm',
      sessionId: args.record.signingGrantId,
      remainingUses: 1,
      expiresAtMs: 1_900_000_000_000,
    },
    state: 'ready',
  };
}

test.describe('EVM-family step-up provision-plan builders', () => {
  test('buildEvmFamilyPasskeyEcdsaProvisionPlan returns a passkey provision branch', async () => {
    const record = makeRecord();
    const material = makeReadyMaterial({
      record,
      authMethod: 'passkey',
      source: 'login',
    });

    const plan = await buildEvmFamilyPasskeyEcdsaProvisionPlan({
      authorization: {
        kind: 'passkey',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.PasskeyReauth,
          method: 'passkey',
        },
        credential: TEST_WEBAUTHN_CREDENTIAL,
        plannedPasskeyReconnect: {
          webauthnChallenge: {
            kind: 'ecdsa_role_local_bootstrap',
            digest32B64u: 'policy-digest-1',
            requestId: 'request-1',
            thresholdSessionId: 'threshold-session-2',
            signingGrantId: 'wallet-session-2',
          },
        },
      },
      material: {
        kind: 'session_record',
        lane: {
          key: material.key,
          keyHandle: material.record.keyHandle,
          chainTarget: material.record.chainTarget,
        },
        record: material.record,
      },
      sessionBudgetUses: 1,
    });
    expect(plan.kind).toBe('passkey_ecdsa_session_provision');
    expect(plan.newSessionIdentity).toEqual({
      thresholdSessionId: 'threshold-session-2',
      signingGrantId: 'wallet-session-2',
    });
    expect(plan.requestId).toBe('request-1');
    expect(plan.provisionSecretSource.passkeyPrfFirstB64u).toBe(TEST_PRF_FIRST_B64U);
  });

  test('passkey ECDSA provision can mint a fresh session from existing record material', async () => {
    const existingRecord = makeRecord();
    const refreshedRecord = makeRecordWithIdentity({
      thresholdSessionId: 'threshold-session-2',
      signingGrantId: 'wallet-session-2',
    });
    const existingMaterial = makeReadyMaterial({
      record: existingRecord,
      authMethod: 'passkey',
      source: 'login',
    });
    const refreshedMaterial = makeReadyMaterial({
      record: refreshedRecord,
      authMethod: 'passkey',
      source: 'login',
    });
    const plan = await buildEvmFamilyPasskeyEcdsaProvisionPlan({
      authorization: {
        kind: 'passkey',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.PasskeyReauth,
          method: 'passkey',
        },
        credential: TEST_WEBAUTHN_CREDENTIAL,
        plannedPasskeyReconnect: {
          webauthnChallenge: {
            kind: 'ecdsa_role_local_bootstrap',
            digest32B64u: 'policy-digest-1',
            requestId: 'request-1',
            thresholdSessionId: refreshedRecord.thresholdSessionId,
            signingGrantId: refreshedRecord.signingGrantId,
          },
        },
      },
      material: {
        kind: 'session_record',
        lane: {
          key: existingMaterial.key,
          keyHandle: existingMaterial.record.keyHandle,
          chainTarget: existingMaterial.record.chainTarget,
        },
        record: existingMaterial.record,
      },
      sessionBudgetUses: 1,
    });
    let provisionCalls = 0;
    let provisioned = false;

    const result = await ensureWarmEcdsaCapabilityReady(
      {
        getWarmSession: async () => ({
          walletId: toWalletId('alice.testnet'),
          updatedAtMs: 1_800_000_000_000,
          capabilities: {
            ed25519: {
              capability: 'ed25519',
              record: null,
              auth: null,
              prfClaim: null,
              state: 'missing',
            },
            ecdsa: {
              evm: provisioned
                ? makeReadyEcdsaCapability({
                    record: refreshedRecord,
                    material: refreshedMaterial,
                  })
                : makeReadyEcdsaCapability({
                    record: existingRecord,
                    material: existingMaterial,
                  }),
              tempo: {
                capability: 'ecdsa',
                record: null,
                key: null,
                lane: null,
                auth: null,
                prfClaim: null,
                state: 'missing',
              },
            },
          },
        }),
        listThresholdEcdsaRecordsForWalletTarget: () => [
          { source: 'login', record: existingRecord },
          ...(provisioned ? [{ source: 'login' as const, record: refreshedRecord }] : []),
        ],
        canProvisionEcdsaCapability: true,
        provisionThresholdEcdsaSession: async () => {
          provisionCalls += 1;
          provisioned = true;
          return {
            thresholdEcdsaKeyRef: buildThresholdEcdsaSecp256k1KeyRefFromRecord({
              record: refreshedRecord,
            }),
	            keygen: {
	              ok: true,
	              walletKeyId: refreshedRecord.authMetadata.walletKeyId,
	              chainId: CHAIN_TARGET.chainId,
	            },
            session: {
              ok: true,
              thresholdSessionId: refreshedRecord.thresholdSessionId,
              signingGrantId: refreshedRecord.signingGrantId,
              expiresAtMs: 1_900_000_000_000,
              remainingUses: 1,
            },
          };
        },
        touchConfirm: {},
        resolveExactEcdsaRecord: ({ lane }) =>
          String(lane.thresholdSessionId) === refreshedRecord.thresholdSessionId
            ? { kind: 'found', record: refreshedRecord }
            : String(lane.thresholdSessionId) === existingRecord.thresholdSessionId
              ? { kind: 'found', record: existingRecord }
              : { kind: 'not_found' },
        readEcdsaCapabilityForLane: async (lane) =>
          String(lane.thresholdSessionId) === refreshedRecord.thresholdSessionId && provisioned
            ? makeReadyEcdsaCapability({
                record: refreshedRecord,
                material: refreshedMaterial,
              })
            : null,
        reconnectInFlightByCapability: new Map(),
      },
      {
        walletId: toWalletId('alice.testnet'),
        source: 'login',
        chainTarget: CHAIN_TARGET,
        sessionBudgetUses: 1,
        usesNeeded: 1,
        record: existingRecord,
        plan,
      },
    );

    expect(provisionCalls).toBe(1);
    expect(result.reconnected).toBe(true);
    expect(result.record.thresholdSessionId).toBe('threshold-session-2');
    expect(result.record.signingGrantId).toBe('wallet-session-2');
  });

  test('buildEvmFamilyWarmSessionReconnectPlan returns a threshold-session reconnect branch', () => {
    const record = makeRecord();
    const material = makeReadyMaterial({
      record,
      authMethod: 'passkey',
      source: 'login',
    });

    const plan = buildEvmFamilyWarmSessionReconnectPlan({
      authorization: {
        kind: 'warm_session',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.WarmSession,
          method: 'passkey',
          accountId: 'alice.testnet',
          intent: 'transaction_sign',
          curve: 'ecdsa',
          sessionId: 'wallet-session-1',
          expiresAtMs: 1_900_000_000_000,
          remainingUses: 2,
        },
        sessionId: 'wallet-session-1',
        expiresAtMs: 1_900_000_000_000,
        remainingUses: 2,
      },
      material,
      sessionBudgetUses: 1,
    });

    expect(plan.kind).toBe('wallet_session_ecdsa_reconnect');
    if (plan.kind !== 'wallet_session_ecdsa_reconnect') {
      throw new Error('expected wallet_session_ecdsa_reconnect');
    }
    expect(plan.walletSessionAuth.identity).toEqual({
      thresholdSessionId: 'threshold-session-1',
      signingGrantId: 'wallet-session-1',
    });
  });
});
