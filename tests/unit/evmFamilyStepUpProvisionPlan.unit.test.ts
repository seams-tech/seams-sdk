import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import { toWalletSubjectId, type ThresholdEcdsaChainTarget } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../client/src/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSessionRecord } from '../../client/src/core/signingEngine/session/persistence/records';
import { buildEvmFamilyEcdsaSigningLaneContext } from '../../client/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes';
import {
  buildEvmFamilyEmailOtpEcdsaProvisionPlan,
  buildEvmFamilyPasskeyEcdsaProvisionPlan,
  buildEvmFamilyWarmSessionReconnectPlan,
} from '../../client/src/core/signingEngine/flows/signEvmFamily/provisionPlan';
import { SigningAuthPlanKind } from '../../client/src/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '../../client/src/core/types/webauthn';

const CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};

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
        first: 'first-prf',
        second: undefined,
      },
    },
  },
} satisfies WebAuthnAuthenticationCredential;

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

function makeKeyRef(): ThresholdEcdsaSecp256k1KeyRef {
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: 'alice.testnet',
    subjectId: toWalletSubjectId('wallet-1'),
    chainTarget: CHAIN_TARGET,
    relayerUrl: 'https://relayer.test',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    backendBinding: {
      relayerKeyId: 'relayer-key-1',
      clientVerifyingShareB64u: 'verifying-share',
    },
    participantIds: [1, 2, 3],
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken: makeThresholdSessionAuthToken({
      thresholdSessionId: 'threshold-session-1',
      walletSigningSessionId: 'wallet-session-1',
    }),
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-session-1',
  };
}

function makeRecord(): ThresholdEcdsaSessionRecord {
  return {
    nearAccountId: toAccountId('alice.testnet'),
    subjectId: toWalletSubjectId('wallet-1'),
    chainTarget: CHAIN_TARGET,
    relayerUrl: 'https://relayer.test',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'root-1',
    signingRootVersion: 'v1',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: 'verifying-share',
    participantIds: [1, 2, 3],
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
      policy: 'default',
      retention: 'session',
      reason: 'sign',
      authMethod: 'email_otp',
    },
  };
}

function makeLane(record: ThresholdEcdsaSessionRecord, keyRef: ThresholdEcdsaSecp256k1KeyRef) {
  const lane = buildEvmFamilyEcdsaSigningLaneContext({
    nearAccountId: 'alice.testnet',
    chain: 'evm',
    chainTarget: CHAIN_TARGET,
    authMethod: 'passkey',
    source: 'login',
    material: 'record_and_key_ref',
    record: {
      ...record,
      source: 'login',
      emailOtpAuthContext: undefined,
    },
    keyRef,
  });
  if (!lane) {
    throw new Error('expected EVM-family ECDSA lane');
  }
  return lane;
}

test.describe('EVM-family step-up provision-plan builders', () => {
  test('buildEvmFamilyPasskeyEcdsaProvisionPlan returns a passkey provision branch', () => {
    const keyRef = makeKeyRef();
    const record = makeRecord();
    const lane = makeLane(record, keyRef);

    const plan = buildEvmFamilyPasskeyEcdsaProvisionPlan({
      authorization: {
        kind: 'passkey',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.PasskeyReauth,
          method: 'passkey',
        },
        credential: TEST_WEBAUTHN_CREDENTIAL,
        plannedPasskeyReconnect: {
          sessionId: 'threshold-session-2',
          walletSigningSessionId: 'wallet-session-2',
          sessionPolicyDigest32: 'policy-digest-1',
        },
      },
      lane,
      keyRef,
      record,
      sessionBudgetUses: 1,
    });

    expect(plan.kind).toBe('passkey_ecdsa_session_provision');
    expect(plan.newSessionIdentity).toEqual({
      thresholdSessionId: 'threshold-session-2',
      walletSigningSessionId: 'wallet-session-2',
    });
    expect(plan.clientRootShare32B64u).toBe('first-prf');
  });

  test('buildEvmFamilyWarmSessionReconnectPlan returns a threshold-session reconnect branch', () => {
    const keyRef = makeKeyRef();
    const record = {
      ...makeRecord(),
      source: 'login',
      emailOtpAuthContext: undefined,
    };
    const lane = makeLane(record, keyRef);

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
      lane,
      keyRef,
      record,
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

  test('buildEvmFamilyEmailOtpEcdsaProvisionPlan returns an email-otp provision branch', () => {
    const keyRef = makeKeyRef();
    const record = makeRecord();

    const plan = buildEvmFamilyEmailOtpEcdsaProvisionPlan({
      authorization: {
        kind: 'email_otp',
        signingAuthPlan: {
          kind: SigningAuthPlanKind.EmailOtpReauth,
          method: 'email_otp',
        },
        challengeId: 'otp-1',
        otpCode: '123456',
        emailHint: 'a***@x.test',
      },
      keyRef,
      record,
      chainTarget: CHAIN_TARGET,
      clientRootShare32B64u: 'client-root-share',
      sessionBudgetUses: 1,
    });

    expect(plan.kind).toBe('email_otp_ecdsa_session_provision');
    expect(plan.newSessionIdentity).toEqual({
      thresholdSessionId: 'threshold-session-1',
      walletSigningSessionId: 'wallet-session-1',
    });
    expect(plan.emailOtpAuthContext.reason).toBe('sign');
  });
});
