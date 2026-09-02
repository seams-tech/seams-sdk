/**
 * Refactor 109C: remove one auth method using a different active one.
 *
 * The inverse of the two addition branches, and the reason they are safe to
 * offer: a wallet that can gain a second way in must be able to lose one it no
 * longer trusts. The proof comes from a sibling, never from the method being
 * removed, so losing a credential does not also lose the ability to retire it.
 *
 * Deliberately not `devices.revokeLinkedDevice`. That path authenticates an
 * owner *request* against the device-linking management service; a sibling on
 * this device is not a linked device, and the wallet's own auth-method route
 * wants a factor proof bound to this exact revocation instead.
 */
import { toError } from '@shared/utils/errors';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseWalletAuthMethodRecordV2,
  computeWalletAuthMethodRevokeOperationFingerprintV1,
  walletIdFromString,
  type WalletId,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { IndexedDBManager } from '@/core/indexedDB';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { passkeyCredentialIdB64uFromAuthentication } from './passkey/ecdsaBootstrap';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';

import { revokeWalletAuthMethod as revokeWalletAuthMethodRoute } from '@/core/rpcClients/relayer/walletRegistration';
import { requestEmailOtpChallenge } from './emailOtp/challenge';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import type { WalletAuthMethodRevocationProof } from '@shared/utils/registrationIntent';
import { WALLET_AUTH_METHODS, type WalletAuthMethod } from '@shared/utils/signerDomain';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import type { ProfileAuthenticatorRecord } from '@/core/indexedDB';

export type RevokeAuthMethodResult = {
  readonly ok: true;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authMethod: { readonly kind: string; readonly status: 'revoked' };
};

/**
 * Every local passkey credential backed by an active V2 method except the one
 * being revoked.
 *
 * Offering the target would let a credential authorize its own removal, which
 * the server refuses anyway - but refusing it here means the prompt never asks
 * for the one credential that cannot answer.
 */
function webAuthnTransportsFromRaw(value: unknown): AuthenticatorTransport[] {
  if (!Array.isArray(value)) return [];
  return value.filter((transport): transport is AuthenticatorTransport =>
    ['ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'].includes(String(transport)),
  );
}

export function passkeySourceCredentialsForActiveMethods(args: {
  readonly walletId: WalletId;
  readonly authenticators: readonly ProfileAuthenticatorRecord[];
  readonly authMethods: readonly WalletAuthMethodRecordV2[];
  readonly excludeCredentialIdB64u: string | null;
}): WebAuthnAllowCredential[] {
  const activeCredentialIds = new Set<string>();
  for (const method of args.authMethods) {
    if (
      method.kind === 'passkey' &&
      method.status === 'active' &&
      method.walletId === args.walletId
    ) {
      activeCredentialIds.add(method.credentialIdB64u);
    }
  }

  const allowCredentials: WebAuthnAllowCredential[] = [];
  for (const record of args.authenticators) {
    const id = String(record.credentialId || '').trim();
    if (!id || id === args.excludeCredentialIdB64u || !activeCredentialIds.has(id)) continue;
    allowCredentials.push({
      id,
      type: 'public-key',
      transports: webAuthnTransportsFromRaw(record.transports),
    });
  }
  return allowCredentials;
}

async function passkeySourceCredentials(args: {
  readonly walletId: WalletId;
  readonly excludeCredentialIdB64u: string | null;
}): Promise<WebAuthnAllowCredential[]> {
  const [authenticators, authMethods] = await Promise.all([
    IndexedDBManager.listProfileAuthenticators(String(args.walletId)),
    IndexedDBManager.listWalletAuthMethodsV2ForWallet(String(args.walletId)),
  ]);
  return passkeySourceCredentialsForActiveMethods({
    walletId: args.walletId,
    authenticators,
    authMethods,
    excludeCredentialIdB64u: args.excludeCredentialIdB64u,
  });
}

async function passkeySourceProof(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly operationFingerprintDigest: string;
  readonly allowCredentials: WebAuthnAllowCredential[];
}): Promise<WalletAuthMethodRevocationProof> {
  const credential = await args.context.signingEngine.getAuthenticationCredentialsSerialized({
    subjectId: String(args.walletId),
    challengeB64u: args.operationFingerprintDigest,
    allowCredentials: args.allowCredentials,
    includeSecondPrfOutput: false,
  });
  const credentialIdB64u = passkeyCredentialIdB64uFromAuthentication(credential);
  if (
    !credentialIdB64u ||
    !args.allowCredentials.some((allowed) => allowed.id === credentialIdB64u)
  ) {
    throw new Error('registration.revokeAuthMethod used a credential outside the wallet');
  }
  return {
    kind: 'webauthn_assertion',
    rpId: args.rpId,
    credential: redactCredentialExtensionOutputs(credential),
    expectedChallengeDigestB64u: args.operationFingerprintDigest,
  };
}

async function emailOtpSourceProof(args: {
  readonly context: RegistrationWebContext;
  readonly relayerUrl: string;
  readonly walletId: WalletId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly operationFingerprintDigest: string;
}): Promise<WalletAuthMethodRevocationProof> {
  const local = await IndexedDBManager.listWalletAuthMethodsForWallet(String(args.walletId));
  const sources = local.filter(
    (method) =>
      method.kind === 'email_otp' &&
      method.status === 'active' &&
      String(method.walletId) === String(args.walletId) &&
      String(method.authority.bindingId) !== String(args.targetWalletAuthMethodId),
  );
  const [source, ...remaining] = sources;
  if (!source || remaining.length > 0 || source.kind !== 'email_otp') {
    throw new Error(
      'registration.revokeAuthMethod needs exactly one other active method to authorize with',
    );
  }
  const walletAuthMethodId = String(source.authority.bindingId);
  const requestChallenge = async () =>
    await requestEmailOtpChallenge({
      relayUrl: args.relayerUrl,
      walletId: String(args.walletId),
      walletAuthMethodId,
      operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      operationFingerprintDigest: parseDigestB64u(args.operationFingerprintDigest),
    });
  const challenge = await requestChallenge();
  const confirmed = await args.context.signingEngine.requestEmailOtpEnrollmentConfirmation({
    walletId: String(args.walletId),
    emailAddress: String(challenge.emailHint || ''),
    challengeId: challenge.challengeId,
    ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
    onResend: async () => {
      const resent = await requestChallenge();
      return resent.emailHint
        ? { challengeId: resent.challengeId, emailHint: resent.emailHint }
        : { challengeId: resent.challengeId };
    },
  });
  return {
    kind: 'email_otp',
    challengeId: confirmed.challengeId,
    otpCode: confirmed.otpCode,
    ownerProofBindingDigest: challenge.ownerProofBindingDigest,
  };
}

async function revokeAuthMethodInternal(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): Promise<RevokeAuthMethodResult> {
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) throw new Error('registration.revokeAuthMethod requires relayer.url');
  const parsedRpId = parseWebAuthnRpId(String(args.context.signingEngine.getRpId() || '').trim());
  if (!parsedRpId.ok) {
    throw new Error(`registration.revokeAuthMethod ${parsedRpId.error.message}`);
  }
  /* The proof is taken over the operation fingerprint, so the assertion
     authorizes this wallet, this target, and this moment - not revocation in
     general. The server recomputes it from the same three values. */
  const requestedAtMs = Date.now();
  const operationFingerprintDigest = await computeWalletAuthMethodRevokeOperationFingerprintV1({
    walletId: args.walletId,
    targetWalletAuthMethodId: args.walletAuthMethodId,
    requestedAtMs,
  });
  const target = await IndexedDBManager.getWalletAuthMethodV2(args.walletAuthMethodId);
  const excludeCredentialIdB64u =
    target && target.kind === 'passkey' ? String(target.credentialIdB64u) : null;
  const allowCredentials = await passkeySourceCredentials({
    walletId: args.walletId,
    excludeCredentialIdB64u,
  });
  /* Whichever family the surviving sibling belongs to proves this. A passkey
     answers with an assertion over the fingerprint; an Email OTP method answers
     with a code against a challenge the server bound to the same fingerprint,
     which is why the binding digest comes back from the challenge rather than
     being computed here. */
  let sourceAuthMethod: WalletAuthMethod;
  if (allowCredentials.length > 0) {
    sourceAuthMethod = WALLET_AUTH_METHODS.passkey;
  } else {
    sourceAuthMethod = WALLET_AUTH_METHODS.emailOtp;
  }
  let sourceProof: WalletAuthMethodRevocationProof;
  switch (sourceAuthMethod) {
    case WALLET_AUTH_METHODS.passkey:
      sourceProof = await passkeySourceProof({
        context: args.context,
        walletId: args.walletId,
        rpId: parsedRpId.value,
        operationFingerprintDigest: String(operationFingerprintDigest),
        allowCredentials,
      });
      break;
    case WALLET_AUTH_METHODS.emailOtp:
      sourceProof = await emailOtpSourceProof({
        context: args.context,
        relayerUrl,
        walletId: args.walletId,
        targetWalletAuthMethodId: args.walletAuthMethodId,
        operationFingerprintDigest: String(operationFingerprintDigest),
      });
      break;
    default:
      sourceAuthMethod satisfies never;
      throw new Error('registration.revokeAuthMethod encountered an unsupported source method');
  }
  const response = await revokeWalletAuthMethodRoute({
    relayerUrl,
    walletId: args.walletId,
    walletAuthMethodId: args.walletAuthMethodId,
    requestedAtMs,
    sourceProof,
  });
  if (!response.ok || response.authMethod.status !== 'revoked') {
    throw new Error('registration.revokeAuthMethod did not revoke the method');
  }
  /* Carry the server's decision into the local record. The wallet builds its
     own view of which methods exist from these rows, so leaving one active
     after the server retired it means the wallet keeps offering a credential
     that can no longer do anything - and, worse, keeps counting it when it
     asks how many methods are left. */
  const local = await IndexedDBManager.getWalletAuthMethodV2(args.walletAuthMethodId);
  if (local && local.status !== 'revoked') {
    const revokedAtMs = Date.now();
    const activatedAtMs = local.status === 'active' ? local.activatedAtMs : revokedAtMs;
    const revoked = parseWalletAuthMethodRecordV2({
      ...local,
      status: 'revoked',
      activatedAtMs,
      revokedAtMs,
      updatedAtMs: revokedAtMs,
    });
    if (revoked) await IndexedDBManager.upsertWalletAuthMethodV2(revoked);
  }
  return {
    ok: true,
    walletId: args.walletId,
    walletAuthMethodId: args.walletAuthMethodId,
    authMethod: response.authMethod,
  };
}

export async function revokeWalletAuthMethodOperation(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId | string;
  readonly walletAuthMethodId: string;
}): Promise<RevokeAuthMethodResult> {
  const walletId = walletIdFromString(String(args.walletId || '').trim());
  const parsedMethodId = parseWalletAuthMethodId(String(args.walletAuthMethodId || '').trim());
  if (!parsedMethodId.ok) {
    throw new Error('registration.revokeAuthMethod requires a wallet auth method id');
  }
  try {
    return await revokeAuthMethodInternal({
      context: args.context,
      walletId,
      walletAuthMethodId: parsedMethodId.value,
    });
  } catch (error: unknown) {
    throw toError(error);
  }
}
