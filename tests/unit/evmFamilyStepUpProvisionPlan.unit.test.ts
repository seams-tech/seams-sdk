import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../../client/src/core/signingEngine/session/persistence/records';
import {
  resolveReadyEvmFamilyEcdsaMaterial,
  toEvmFamilyEcdsaKeyHandle,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEvmFamilyPasskeyEcdsaProvisionPlan,
  buildEvmFamilyWarmSessionReconnectPlan,
} from '../../client/src/core/signingEngine/flows/signEvmFamily/provisionPlan';
import { SigningAuthPlanKind } from '../../client/src/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '../../client/src/core/types/webauthn';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../client/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';

const CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};
const TEST_PRF_FIRST_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_SHARE32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
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

function makeThresholdSessionAuthToken(args: {
  thresholdSessionId: string;
  walletSigningSessionId: string;
}): string {
  const encode = (value: object): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
    sessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    exp: 1_900_000_000,
  })}.signature`;
}

function makeRecord(): ThresholdEcdsaSessionRecord {
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-step-up');
  return {
    walletId: toAccountId('alice.testnet'),
    authMetadata: { rpId: 'example.localhost' },
    chainTarget: CHAIN_TARGET,
    relayerUrl: 'https://relayer.test',
    keyHandle,
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
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
        rpId: 'example.localhost',
        chainTarget: CHAIN_TARGET,
        keyHandle,
        ecdsaThresholdKeyId: 'ecdsa-key-1',
        signingRootId: 'root-1',
        signingRootVersion: 'v1',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        contextBinding32B64u: VALID_ECDSA_SHARE32_B64U,
        hssClientSharePublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        groupPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
        ethereumAddress: THRESHOLD_OWNER_ADDRESS,
      }),
      authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: TEST_PASSKEY_CREDENTIAL_ID_B64U,
        rpId: 'example.localhost',
      }),
    }),
    participantIds: [1, 2],
    ethereumAddress: THRESHOLD_OWNER_ADDRESS,
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-session-1',
    thresholdSessionAuthToken: makeThresholdSessionAuthToken({
      thresholdSessionId: 'threshold-session-1',
      walletSigningSessionId: 'wallet-session-1',
    }),
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 2,
    updatedAtMs: 1_800_000_000_000,
    source: 'login',
  };
}

function makeReadyMaterial(args: {
  record: ThresholdEcdsaSessionRecord;
  authMethod: 'passkey' | 'email_otp';
  source: 'login' | 'email_otp';
}): ReadyEvmFamilyEcdsaMaterial {
  const material = resolveReadyEvmFamilyEcdsaMaterial({
    record: args.record,
    rpId: thresholdEcdsaRecordRpId(args.record),
    expected: {
      walletId: args.record.walletId,
      chainTarget: CHAIN_TARGET,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: args.record.thresholdSessionId,
      walletSigningSessionId: args.record.walletSigningSessionId,
    },
  });
  if (material.kind !== 'ready') {
    throw new Error(`expected ready EVM-family ECDSA material: ${material.kind}`);
  }
  return material.material;
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
            walletSigningSessionId: 'wallet-session-2',
          },
        },
      },
      material,
      sessionBudgetUses: 1,
    });
    expect(plan.kind).toBe('passkey_ecdsa_session_provision');
    expect(plan.newSessionIdentity).toEqual({
      thresholdSessionId: 'threshold-session-2',
      walletSigningSessionId: 'wallet-session-2',
    });
    expect(plan.requestId).toBe('request-1');
    expect(plan.provisionSecretSource.passkeyPrfFirstB64u).toBe(TEST_PRF_FIRST_B64U);
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

    expect(plan.kind).toBe('threshold_session_auth_ecdsa_reconnect');
    if (plan.kind !== 'threshold_session_auth_ecdsa_reconnect') {
      throw new Error('expected threshold_session_auth_ecdsa_reconnect');
    }
    expect(plan.thresholdSessionAuth.identity).toEqual({
      thresholdSessionId: 'threshold-session-1',
      walletSigningSessionId: 'wallet-session-1',
    });
  });
});
