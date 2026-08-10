import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import { IndexedDBManager } from '@/core/indexedDB';
import { resolveManagedRuntimeScopeBootstrap } from '@/core/config/managedRuntimeScope';
import { exchangeSession, type SessionExchangeRuntimeScope } from '@/core/rpcClients/near/rpcCalls';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  passkeyCredentialIdB64uFromAuthentication,
  requirePasskeyPrfFirstB64u,
} from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import {
  rotateWalletRecoverySetWithActiveFactorV1,
  rotateWalletRecoverySetWithEmailOtpV1,
  type WalletRecoveryRotationOutcome,
} from '@/core/signingEngine/walletCustody/walletRecoveryRotation';
import { buildEmailOtpRoutePlan } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import { base64UrlDecode } from '@shared/utils/encoders';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { parsePasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';

export type WalletRecoveryRotationAuthorization =
  | { readonly kind: 'existing_passkey' }
  | { readonly kind: 'email_otp'; readonly challengeId: string; readonly otpCode: string };

function authenticatorTransports(value: unknown): AuthenticatorTransport[] {
  if (!Array.isArray(value)) return [];
  return value.filter((transport): transport is AuthenticatorTransport => {
    switch (transport) {
      case 'ble':
      case 'hybrid':
      case 'internal':
      case 'nfc':
      case 'smart-card':
      case 'usb':
        return true;
      default:
        return false;
    }
  });
}

function passkeyAllowCredentials(
  records: readonly { credentialId: string; transports?: unknown }[],
): WebAuthnAllowCredential[] {
  const credentials = records.flatMap((record) => {
    const id = String(record.credentialId || '').trim();
    return id
      ? [{ id, type: 'public-key' as const, transports: authenticatorTransports(record.transports) }]
      : [];
  });
  if (credentials.length === 0) {
    throw new Error('Wallet recovery-code rotation requires an active passkey');
  }
  return credentials;
}

function sessionExchangeRuntimeScope(context: RegistrationWebContext): SessionExchangeRuntimeScope {
  const managed = resolveManagedRuntimeScopeBootstrap(context.configs);
  return managed
    ? {
        kind: 'managed',
        projectEnvironmentId: managed.projectEnvironmentId,
        publishableKey: managed.publishableKey,
      }
    : { kind: 'unscoped' };
}

async function requestPasskeyUnlockChallenge(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly rpId: string;
}): Promise<{ readonly challengeId: string; readonly challengeB64u: string }> {
  const response = await fetch(joinNormalizedUrl(args.relayUrl, '/wallet/unlock/challenge'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      unlockBackend: 'passkey',
      userId: args.walletId,
      rpId: args.rpId,
    }),
  });
  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};
  if (!response.ok || body.ok !== true) {
    throw new Error(
      typeof body.message === 'string'
        ? body.message
        : `wallet unlock challenge failed (HTTP ${response.status})`,
    );
  }
  const challengeId = String(body.challengeId || '').trim();
  const challengeB64u = String(body.challengeB64u || '').trim();
  if (!challengeId || !challengeB64u) {
    throw new Error('wallet unlock challenge returned an invalid payload');
  }
  return { challengeId, challengeB64u };
}

async function rotateWithPasskey(args: {
  readonly context: RegistrationWebContext;
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
}): Promise<WalletRecoveryRotationOutcome> {
  const rpId = String(args.context.signingEngine.getRpId() || '').trim();
  if (!rpId) throw new Error('Wallet recovery-code rotation requires an RP ID');
  const challenge = await requestPasskeyUnlockChallenge({
    relayUrl: args.relayUrl,
    walletId: args.walletId,
    rpId,
  });
  const authenticators = await IndexedDBManager.listProfileAuthenticators(args.walletId);
  const allowCredentials = passkeyAllowCredentials(authenticators);
  const credential = await args.context.signingEngine.getAuthenticationCredentialsSerialized({
    subjectId: args.walletId,
    challengeB64u: challenge.challengeB64u,
    allowCredentials,
    includeSecondPrfOutput: false,
  });
  const credentialId = passkeyCredentialIdB64uFromAuthentication(credential);
  if (!credentialId || !allowCredentials.some((candidate) => candidate.id === credentialId)) {
    throw new Error('Wallet recovery-code rotation selected an unrelated passkey');
  }
  const factorSecret = base64UrlDecode(
    requirePasskeyPrfFirstB64u(credential, 'Wallet recovery-code rotation'),
  );
  try {
    const exchange = await exchangeSession(
      args.relayUrl,
      '/session/exchange',
      'jwt',
      {
        type: 'passkey_assertion',
        challengeId: challenge.challengeId,
        walletId: args.walletId,
        webauthn_authentication: credential,
        expected_origin: typeof window === 'undefined' ? '' : window.location.origin,
      },
      sessionExchangeRuntimeScope(args.context),
    );
    if (!exchange.success || !exchange.walletCustody) {
      throw new Error(exchange.success ? 'Passkey unlock omitted wallet custody' : exchange.error);
    }
    const envelope = parsePasskeyCustodyEnvelopeRecord(exchange.walletCustody.envelope);
    if (
      envelope.walletId !== args.walletId ||
      envelope.factor.kind !== 'passkey' ||
      envelope.factor.credentialIdB64u !== credentialId
    ) {
      throw new Error('Passkey unlock returned a mismatched custody envelope');
    }
    const worker = args.context.signingEngine.getSignerWorkerContext();
    return await rotateWalletRecoverySetWithActiveFactorV1({
      relayUrl: args.relayUrl,
      walletId: args.walletId,
      sessionToken: args.sessionToken,
      custodyEnvelope: envelope,
      factorSecret: factorSecret.buffer,
      worker: {
        rotateRecoverySet: async (request) =>
          await worker.requestWorkerOperation({
            kind: 'walletCustodyCeremony',
            request: {
              type: 'rotateWalletRecoverySet',
              timeoutMs: 30_000,
              payload: request,
              transfer: [request.factorSecret],
            },
          }),
      },
    });
  } finally {
    factorSecret.fill(0);
  }
}

async function rotateWithEmailOtp(args: {
  readonly context: RegistrationWebContext;
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly authorization: Extract<WalletRecoveryRotationAuthorization, { kind: 'email_otp' }>;
}): Promise<WalletRecoveryRotationOutcome> {
  const worker = args.context.signingEngine.getSignerWorkerContext();
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'login',
    authLane: { kind: 'app_session', jwt: args.sessionToken },
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
  return await rotateWalletRecoverySetWithEmailOtpV1({
    relayUrl: args.relayUrl,
    walletId: args.walletId,
    sessionToken: args.sessionToken,
    worker: {
      rotateRecoverySet: async ({ recoveryCodesJson }) =>
        await worker.requestWorkerOperation({
          kind: 'emailOtp',
          request: {
            type: 'rotateEmailOtpWalletRecoverySet',
            timeoutMs: 60_000,
            payload: {
              relayUrl: args.relayUrl,
              walletId: args.walletId,
              userId: args.walletId,
              groupId: SIGNING_SESSION_SEAL_GROUP_ID,
              routePlan,
              verification: {
                kind: 'otp',
                challengeId: args.authorization.challengeId,
                otpCode: args.authorization.otpCode,
              },
              recoveryCodesJson,
            },
          },
        }),
    },
  });
}

export async function rotateWalletRecoveryCodes(args: {
  readonly context: RegistrationWebContext;
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly authorization: WalletRecoveryRotationAuthorization;
}): Promise<WalletRecoveryRotationOutcome> {
  switch (args.authorization.kind) {
    case 'existing_passkey':
      return await rotateWithPasskey(args);
    case 'email_otp':
      return await rotateWithEmailOtp({ ...args, authorization: args.authorization });
  }
}
