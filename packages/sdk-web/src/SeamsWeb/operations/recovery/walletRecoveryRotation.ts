import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import { IndexedDBManager } from '@/core/indexedDB';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  passkeyCredentialIdB64uFromAuthentication,
  requirePasskeyPrfFirstB64u,
} from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import {
  rotateWalletRecoverySetWithActiveFactorV1,
  rotateWalletRecoverySetWithEmailOtpV1,
  type WalletRecoveryRotationOutcome,
  type WalletRecoveryFactorProofFactory,
} from '@/core/signingEngine/walletCustody/walletRecoveryRotation';
import {
  requestWalletCustodyEmailOtpChallenge,
  type WalletCustodyFactorProof,
} from '@/core/rpcClients/relayer/walletRecoveryRotate';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
import { buildEmailOtpRoutePlan } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import { base64UrlDecode } from '@shared/utils/encoders';
import { fetchPasskeyCustodyEnvelope } from '@/core/rpcClients/relayer/passkeyCustodyEnvelope';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { parsePasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { computeWalletCustodyAdminChallengeDigest } from '@shared/authorization/walletCustodyOperation';
import type { WalletCustodyAdminOperation } from '@shared/authorization/walletCustodyOperation';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';

export type WalletRecoveryRotationAuthorization =
  | { readonly kind: 'existing_passkey' }
  | {
      readonly kind: 'email_otp';
      readonly providerSubjectId: string;
      readonly challengeId: string;
      readonly challenge_digest: string;
      readonly otpCode: string;
    };

export async function buildWalletCustodyPasskeyFactorProof(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: string;
  readonly operation: WalletCustodyAdminOperation;
  readonly payload: Record<string, unknown>;
}): Promise<WalletCustodyFactorProof> {
  const requestOrigin = typeof window === 'undefined' ? '' : window.location.origin;
  if (!requestOrigin) throw new Error('Wallet custody administration requires a browser Origin');
  const rpId = String(args.context.signingEngine.getRpId() || '').trim();
  if (!rpId) throw new Error('Wallet custody administration requires an RP ID');
  const challengeDigest = await computeWalletCustodyAdminChallengeDigest({
    walletId: args.walletId,
    operation: args.operation,
    payload: args.payload,
    requestOrigin,
  });
  const authenticators = await IndexedDBManager.listProfileAuthenticators(args.walletId);
  const allowCredentials = passkeyAllowCredentials(authenticators);
  const credential = await args.context.signingEngine.getAuthenticationCredentialsSerialized({
    subjectId: args.walletId,
    challengeB64u: challengeDigest,
    allowCredentials,
    includeSecondPrfOutput: false,
  });
  const credentialId = passkeyCredentialIdB64uFromAuthentication(credential);
  if (!credentialId || !allowCredentials.some((candidate) => candidate.id === credentialId)) {
    throw new Error('Wallet custody administration selected an unrelated passkey');
  }
  return {
    kind: 'passkey',
    walletId: args.walletId,
    rpId,
    credentialIdB64u: credentialId,
    challenge_digest: challengeDigest,
    webauthn_authentication: credential,
  };
}

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

async function requestPasskeyEnvelopeChallenge(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly rpId: string;
}): Promise<{ readonly challengeId: string; readonly challengeB64u: string }> {
  const response = await fetch(joinNormalizedUrl(args.relayUrl, '/wallet/unlock/challenge'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ unlockBackend: 'passkey', userId: args.walletId, rpId: args.rpId }),
  });
  const value: unknown = await response.json().catch(() => ({}));
  const body = value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
  if (!response.ok || body.ok !== true) {
    throw new Error(typeof body.message === 'string' ? body.message : 'passkey envelope challenge failed');
  }
  const challengeId = typeof body.challengeId === 'string' ? body.challengeId.trim() : '';
  const challengeB64u = typeof body.challengeB64u === 'string' ? body.challengeB64u.trim() : '';
  if (!challengeId || !challengeB64u) throw new Error('passkey envelope challenge is invalid');
  return { challengeId, challengeB64u };
}

async function rotateWithPasskey(args: {
  readonly context: RegistrationWebContext;
  readonly relayUrl: string;
  readonly walletId: string;
}): Promise<WalletRecoveryRotationOutcome> {
  const rpId = String(args.context.signingEngine.getRpId() || '').trim();
  if (!rpId) throw new Error('Wallet recovery-code rotation requires an RP ID');
  const requestOrigin = typeof window === 'undefined' ? '' : window.location.origin;
  if (!requestOrigin) throw new Error('Wallet recovery-code rotation requires a browser Origin');
  const authenticators = await IndexedDBManager.listProfileAuthenticators(args.walletId);
  const allowCredentials = passkeyAllowCredentials(authenticators);
  const envelopeChallenge = await requestPasskeyEnvelopeChallenge({
    relayUrl: args.relayUrl,
    walletId: args.walletId,
    rpId,
  });
  const envelopeCredential = await args.context.signingEngine.getAuthenticationCredentialsSerialized({
    subjectId: args.walletId,
    challengeB64u: envelopeChallenge.challengeB64u,
    allowCredentials,
    includeSecondPrfOutput: true,
  });
  const envelopeCredentialId = passkeyCredentialIdB64uFromAuthentication(envelopeCredential);
  if (!envelopeCredentialId) throw new Error('Wallet recovery-code rotation did not receive a passkey credential');
  const fetchedEnvelope = await fetchPasskeyCustodyEnvelope({
    relayUrl: args.relayUrl,
    locator: {
      walletId: args.walletId,
      factor: { kind: 'passkey', rpId, credentialIdB64u: envelopeCredentialId },
    },
    challengeId: envelopeChallenge.challengeId,
    expectedOrigin: requestOrigin,
    webauthnAuthentication: redactCredentialExtensionOutputs(envelopeCredential),
  });
  if (fetchedEnvelope.kind !== 'active') throw new Error(fetchedEnvelope.message);
  const envelope = parsePasskeyCustodyEnvelopeRecord(fetchedEnvelope.envelope);
  const factorSecret = base64UrlDecode(
    requirePasskeyPrfFirstB64u(envelopeCredential, 'Wallet recovery-code rotation'),
  );
  try {
    const worker = args.context.signingEngine.getSignerWorkerContext();
    const factorProof: WalletRecoveryFactorProofFactory = async ({ operation, payload }) => {
      const challengeDigest = await computeWalletCustodyAdminChallengeDigest({
        walletId: args.walletId,
        operation,
        payload,
        requestOrigin,
      });
      const adminCredential = await args.context.signingEngine.getAuthenticationCredentialsSerialized({
        subjectId: args.walletId,
        challengeB64u: challengeDigest,
        allowCredentials,
        includeSecondPrfOutput: false,
      });
      const adminCredentialId = passkeyCredentialIdB64uFromAuthentication(adminCredential);
      if (!adminCredentialId || adminCredentialId !== envelopeCredentialId) {
        throw new Error('Wallet recovery-code rotation selected an unrelated passkey');
      }
      return {
        kind: 'passkey',
        walletId: args.walletId,
        rpId,
        credentialIdB64u: envelopeCredentialId,
        challenge_digest: challengeDigest,
        webauthn_authentication: adminCredential,
      };
    };
    return await rotateWalletRecoverySetWithActiveFactorV1({
      relayUrl: args.relayUrl,
      walletId: args.walletId,
      factorProof,
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
  readonly authorization: Extract<WalletRecoveryRotationAuthorization, { kind: 'email_otp' }>;
}): Promise<WalletRecoveryRotationOutcome> {
  const worker = args.context.signingEngine.getSignerWorkerContext();
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'login',
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
  const factorProof: WalletRecoveryFactorProofFactory = async ({ operation, payload }) => {
    const requestOrigin = typeof window === 'undefined' ? '' : window.location.origin;
    const challenge = await requestWalletCustodyEmailOtpChallenge({
      relayUrl: args.relayUrl,
      walletId: args.walletId,
      providerSubjectId: args.authorization.providerSubjectId,
      operation,
      payload,
      ...(requestOrigin ? { requestOrigin } : {}),
    });
    if (challenge.kind !== 'ready') throw new Error(challenge.message);
    const challengeDigest = await computeWalletCustodyAdminChallengeDigest({
      walletId: args.walletId,
      operation,
      payload,
      requestOrigin,
    });
    if (
      challenge.challengeId !== args.authorization.challengeId ||
      challenge.challenge_digest !== args.authorization.challenge_digest ||
      challengeDigest !== args.authorization.challenge_digest
    ) {
      throw new Error('Wallet recovery Email OTP challenge is bound to a different operation');
    }
    return {
      kind: 'email_otp',
      provider_subject_id: args.authorization.providerSubjectId,
      challenge_id: args.authorization.challengeId,
      otp_code: args.authorization.otpCode,
      challenge_digest: challengeDigest,
    };
  };
  return await rotateWalletRecoverySetWithEmailOtpV1({
    relayUrl: args.relayUrl,
    walletId: args.walletId,
    factorProof,
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
              verification: { kind: 'otp', challengeId: args.authorization.challengeId, otpCode: args.authorization.otpCode },
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
  readonly authorization: WalletRecoveryRotationAuthorization;
}): Promise<WalletRecoveryRotationOutcome> {
  switch (args.authorization.kind) {
    case 'existing_passkey':
      return await rotateWithPasskey(args);
    case 'email_otp':
      return await rotateWithEmailOtp({ ...args, authorization: args.authorization });
  }
}
