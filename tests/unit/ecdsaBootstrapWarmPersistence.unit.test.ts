import { expect, test } from '@playwright/test';
import {
  buildEmailOtpWorkerIssuedSessionHandle,
  type EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  resolvePasskeyEcdsaBootstrapPersistenceSource,
  type EcdsaBootstrapRequest,
} from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import { shouldEnsurePasskeyEcdsaSealAfterProvision } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import { toEmailOtpAuthSubjectId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { parseWalletKeyId } from '@shared/signing-lanes';

function parsedDomain<T>(
  result: { ok: true; value: T } | { ok: false; error: { message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

const walletId = toWalletId('wallet.testnet');
const walletKeyId = parsedDomain(parseWalletKeyId('wallet-key-bootstrap-warm'));
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
});
const sessionIdentity = buildEcdsaSessionIdentity({
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
});
const thresholdSessionId = SigningSessionIds.thresholdEcdsaSession('threshold-session-1');

function emailOtpWorkerSessionHandle(): Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
> {
  const handle = buildEmailOtpWorkerIssuedSessionHandle({
    sessionId: 'email-otp-worker-session-1',
    walletId,
    walletKeyId,
    authSubjectId: toEmailOtpAuthSubjectId('google:alice'),
    action: 'threshold_ecdsa_bootstrap',
    operation: 'sign',
    chainTarget,
  });
  if (handle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('expected ECDSA worker session handle');
  }
  return handle;
}

function webauthnAuthentication(): WebAuthnAuthenticationCredential {
  return {
    id: 'credential-id-b64u',
    rawId: 'credential-id-b64u',
    type: 'public-key',
    authenticatorAttachment: undefined,
    response: {
      clientDataJSON: 'client-data-json-b64u',
      authenticatorData: 'authenticator-data-b64u',
      signature: 'signature-b64u',
      userHandle: undefined,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: undefined,
          second: undefined,
        },
      },
    },
  };
}

test.describe('ECDSA bootstrap warm persistence branches', () => {
  test('Email OTP bootstrap skips passkey PRF persistence branches', () => {
    const request = {
      kind: 'email_otp_ecdsa_bootstrap',
      walletId,
      chainTarget,
      source: 'email_otp',
      sessionKind: 'jwt',
      sessionIdentity,
      emailOtpWorkerSessionHandle: emailOtpWorkerSessionHandle(),
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'sign',
        authMethod: 'email_otp',
      },
    } satisfies EcdsaBootstrapRequest;

    expect(shouldEnsurePasskeyEcdsaSealAfterProvision(request)).toBe(false);
    expect(
      resolvePasskeyEcdsaBootstrapPersistenceSource({
        request,
        thresholdSessionId,
      }),
    ).toBeNull();
  });

  test('passkey WebAuthn bootstrap keeps passkey PRF persistence enabled', () => {
    const request = {
      kind: 'passkey_fresh_ecdsa_bootstrap',
      walletId,
      chainTarget,
      source: 'registration',
      sessionKind: 'jwt',
      sessionIdentity,
      routeAuth: {
        kind: 'wallet_session',
        jwt: 'threshold-session-jwt',
      },
      webauthnAuthentication: webauthnAuthentication(),
    } satisfies EcdsaBootstrapRequest;

    expect(shouldEnsurePasskeyEcdsaSealAfterProvision(request)).toBe(true);
    expect(
      resolvePasskeyEcdsaBootstrapPersistenceSource({
        request,
        thresholdSessionId,
      }),
    ).toEqual({
      kind: 'fresh_webauthn',
      credentialIdB64u: 'credential-id-b64u',
    });
  });
});
