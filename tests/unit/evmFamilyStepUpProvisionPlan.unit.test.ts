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
import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst } from '../../client/src/core/signingEngine/session/passkey/ecdsaClientRoot';
import { SigningAuthPlanKind } from '../../client/src/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '../../client/src/core/types/webauthn';

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
  return {
    walletId: toAccountId('alice.testnet'),
    authMetadata: { rpId: 'example.localhost' },
    chainTarget: CHAIN_TARGET,
    relayerUrl: 'https://relayer.test',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-step-up'),
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
    clientAdditiveShare32B64u: VALID_ECDSA_SHARE32_B64U,
    ecdsaHssRoleLocalClientState: {
      kind: 'role_local_ready',
      artifactKind: 'ecdsa-hss-role-local-client-state',
      contextBinding32B64u: VALID_ECDSA_SHARE32_B64U,
      clientShare32B64u: VALID_ECDSA_SHARE32_B64U,
      clientPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      clientShareRetryCounter: 0,
      relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress: THRESHOLD_OWNER_ADDRESS,
      clientCaitSithInput: {
        participantId: 1,
        mappedPrivateShare32B64u: VALID_ECDSA_SHARE32_B64U,
        verifyingShare33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      },
      createdAtMs: 1_800_000_000_000,
      updatedAtMs: 1_800_000_000_000,
    },
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
    source: 'email_otp',
    emailOtpAuthContext: {
      policy: 'session',
      retention: 'session',
      reason: 'sign',
      authMethod: 'email_otp',
    },
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
    const record: ThresholdEcdsaSessionRecord = {
      ...makeRecord(),
      source: 'login',
      emailOtpAuthContext: undefined,
    };
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
    const expectedClientRootShare32B64u =
      await derivePasskeyThresholdEcdsaClientRootShare32B64uFromPrfFirst(TEST_PRF_FIRST_B64U);

    expect(plan.kind).toBe('passkey_ecdsa_session_provision');
    expect(plan.newSessionIdentity).toEqual({
      thresholdSessionId: 'threshold-session-2',
      walletSigningSessionId: 'wallet-session-2',
    });
    expect(plan.requestId).toBe('request-1');
    expect(plan.provisionSecretSource.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
  });

  test('buildEvmFamilyWarmSessionReconnectPlan returns a threshold-session reconnect branch', () => {
    const record: ThresholdEcdsaSessionRecord = {
      ...makeRecord(),
      source: 'login' as const,
      emailOtpAuthContext: undefined,
    };
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
