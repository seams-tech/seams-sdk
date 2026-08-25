/**
 * Refactor 109C's `passkey_to_email_otp` branch: a wallet that unlocks with a
 * passkey gains an Email OTP method on the same authority.
 *
 * One new `WalletAuthMethodRecordV2` and one custody envelope. No authority,
 * no signer activation, no share, no public key, no export root, no key
 * manifest — the seed is the wallet's existing one, opened under the passkey
 * the caller just presented and resealed under the verified Email factor. The
 * seed never leaves the worker; what comes back is ciphertext.
 *
 * The caller supplies an address and nothing else. The code is sent by the
 * server to the address the intent already names, and typed into the wallet's
 * own confirmation surface — the same channel key export uses — so it never
 * passes through the host application.
 */
import type { AfterCall, RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import {
  createWalletAddAuthMethodIntent,
  requestAddAuthMethodEmailOtpChallenge,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  computeAddAuthMethodIntentDigestB64u,
  walletIdFromString,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { base64UrlDecode } from '@shared/utils/base64';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { toError } from '@shared/utils/errors';
import { resolveManagedRuntimeScopeBootstrap } from '@/core/config/managedRuntimeScope';
import { IndexedDBManager } from '@/core/indexedDB';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { resolveAddAuthMethodSourceClaimV1 } from '../addAuthMethodSourceClaim';
import { collectEmailOtpRegistrationAuthority } from './registrationAuthority';
import {
  passkeyCredentialIdB64uFromAuthentication,
  requirePasskeyPrfFirstB64u,
} from '../passkey/ecdsaBootstrap';
import { linkWalletEmailOtpCustody } from '@/core/signingEngine/walletCustody/emailOtpLink';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import { persistFinalizedEmailOtpAuthMethodV1 } from './localEmailOtpProjection';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { copyWalletCustodyEcdsaContinuityToAuthMethod } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';

export type AddEmailOtpResult = {
  readonly ok: true;
  readonly walletId: WalletId;
  readonly emailAddress: string;
  readonly authMethod: {
    readonly kind: 'email_otp';
    readonly status: 'active';
  };
};

export type AddEmailOtpHooksOptions = Omit<RegistrationHooksOptions, 'afterCall'> & {
  readonly afterCall?: AfterCall<AddEmailOtpResult>;
};

function webAuthnTransportsFromRaw(value: unknown): AuthenticatorTransport[] {
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

function requireExistingPasskeyCredentials(
  records: readonly { credentialId: string; transports?: unknown }[],
): WebAuthnAllowCredential[] {
  const allowCredentials: WebAuthnAllowCredential[] = [];
  for (const record of records) {
    const id = String(record.credentialId || '').trim();
    if (id) {
      allowCredentials.push({
        id,
        type: 'public-key',
        transports: webAuthnTransportsFromRaw(record.transports),
      });
    }
  }
  if (allowCredentials.length === 0) {
    throw new Error('Wallet add-email-code requires an existing passkey credential');
  }
  return allowCredentials;
}

function walletCustodyWorkerTransport(
  context: RegistrationWebContext,
): WalletCustodyCeremonyTransportPort {
  const workerContext = context.signingEngine.getSignerWorkerContext();
  return {
    requestOperation: async ({ kind, request }) =>
      await workerContext.requestWorkerOperation({
        kind,
        request: request as never,
      }),
  };
}

/**
 * The provider identity an added Email OTP method enrols under.
 *
 * There is no external IdP on this branch — the address is verified by the
 * one-use code, so the address is the identity. Google-backed additions arrive
 * through their own proof kind and carry the Google subject instead.
 */
function providerSubjectForVerifiedAddress(emailAddress: string): string {
  return emailAddress;
}

function normalizedEmailAddress(value: string): string {
  const email = String(value || '')
    .trim()
    .toLowerCase();
  if (!email || !email.includes('@')) {
    throw new Error('registration.addEmailOtp requires an email address');
  }
  return email;
}

async function addEmailOtpWalletAuthMethodInternal(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly emailAddress: string;
  readonly options?: AddEmailOtpHooksOptions;
}): Promise<AddEmailOtpResult> {
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) throw new Error('registration.addEmailOtp requires relayer.url');
  const managedRuntimeScope = resolveManagedRuntimeScopeBootstrap(args.context.configs);
  if (!managedRuntimeScope) {
    throw new Error(
      'registration.addEmailOtp requires registration.publishableKey and registration.projectEnvironmentId',
    );
  }
  const emailAddress = normalizedEmailAddress(args.emailAddress);
  const providerSubject = providerSubjectForVerifiedAddress(emailAddress);
  /* The source proof is a WebAuthn assertion, so this addition still has an RP.
     It is the wallet's, not the new factor's — an Email OTP method has no RP of
     its own. */
  const parsedRpId = parseWebAuthnRpId(String(args.context.signingEngine.getRpId() || '').trim());
  if (!parsedRpId.ok) throw new Error(`registration.addEmailOtp ${parsedRpId.error.message}`);
  const rpId = parsedRpId.value;

  /* R109C: the intent names the source it is minted for, so the fresh
     assertion taken over its digest binds the wallet, authority, source
     method, source session, authority state, and the server-allocated target
     method id. */
  const sourceClaim = await resolveAddAuthMethodSourceClaimV1(args.walletId);
  if (sourceClaim.kind !== 'resolved') {
    throw new Error(
      `Wallet add-email-code requires a selected active source: ${sourceClaim.reason}`,
    );
  }
  const intentResponse = await createWalletAddAuthMethodIntent({
    relayerUrl,
    walletId: args.walletId,
    request: {
      walletId: args.walletId,
      rpId: String(rpId),
      authMethod: { kind: 'email_otp', email: emailAddress },
      caller: { caller: 'same_device_addition', source: sourceClaim.source },
    },
    auth: {
      publishableKey: managedRuntimeScope.publishableKey,
      environmentId: managedRuntimeScope.projectEnvironmentId,
    },
  });
  const intentDigestB64u = await computeAddAuthMethodIntentDigestB64u(intentResponse.intent);
  if (intentDigestB64u !== intentResponse.addAuthMethodIntentDigestB64u) {
    throw new Error('Add-auth-method intent digest mismatch');
  }
  if (
    intentResponse.intent.walletId !== args.walletId ||
    intentResponse.intent.authMethod.kind !== 'email_otp' ||
    intentResponse.intent.authMethod.email !== emailAddress
  ) {
    throw new Error('Add-auth-method intent identity changed');
  }

  const profile = await IndexedDBManager.getProfile(String(args.walletId));
  if (
    !profile ||
    !Number.isSafeInteger(profile.defaultSignerSlot) ||
    profile.defaultSignerSlot < 1
  ) {
    throw new Error('Wallet add-email-code requires an initialized wallet profile');
  }

  /* The source proof. Taken over the intent digest, so it authorizes exactly
     this addition and exactly this target method id — and it carries PRF.first,
     which is the only thing that opens the wallet's existing envelope. */
  const authenticators = await IndexedDBManager.listProfileAuthenticators(String(args.walletId));
  const allowCredentials = requireExistingPasskeyCredentials(authenticators);
  const credential = await args.context.signingEngine.getAuthenticationCredentialsSerialized({
    subjectId: String(args.walletId),
    challengeB64u: intentResponse.addAuthMethodIntentDigestB64u,
    allowCredentials,
    includeSecondPrfOutput: false,
  });
  const credentialIdB64u = passkeyCredentialIdB64uFromAuthentication(credential);
  if (!credentialIdB64u || !allowCredentials.some((allowed) => allowed.id === credentialIdB64u)) {
    throw new Error('Wallet add-email-code selected a credential outside the authorized wallet');
  }
  const passkeyPrfFirstB64u = requirePasskeyPrfFirstB64u(
    credential,
    'Wallet add-email-code custody linking',
  );

  /* The code is sent only after the source proof succeeds. An addition the
     wallet could not authorize should not put a code in anyone's inbox. */
  const sendEnrollmentCode = async (): Promise<{ challengeId: string; emailHint: string }> =>
    await requestAddAuthMethodEmailOtpChallenge({
      relayerUrl,
      walletId: args.walletId,
      addAuthMethodIntentGrant: intentResponse.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
    });
  const sent = await sendEnrollmentCode();
  const confirmed = await args.context.signingEngine.requestEmailOtpEnrollmentConfirmation({
    walletId: String(args.walletId),
    emailAddress,
    challengeId: sent.challengeId,
    ...(sent.emailHint ? { emailHint: sent.emailHint } : {}),
    ...(args.options?.confirmerText ? { confirmerText: args.options.confirmerText } : {}),
    ...(args.options?.confirmationConfig
      ? { confirmationConfigOverride: args.options.confirmationConfig }
      : {}),
    onResend: sendEnrollmentCode,
  });

  const emailAuthority = await collectEmailOtpRegistrationAuthority({
    authMethod: {
      kind: 'email_otp',
      proofKind: 'otp_challenge',
      email: emailAddress,
      providerSubject,
      otpCode: confirmed.otpCode,
      challengeId: confirmed.challengeId,
    },
    relayUrl: relayerUrl,
    walletId: String(args.walletId),
    registrationIntentDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
  });

  const existingFactorSecret = base64UrlDecode(passkeyPrfFirstB64u);
  try {
    const linked = await linkWalletEmailOtpCustody({
      context: args.context,
      relayerUrl,
      walletId: args.walletId,
      addAuthMethodIntentGrant: intentResponse.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
      intent: intentResponse.intent,
      auth: {
        kind: 'webauthn_assertion',
        rpId,
        credential: redactCredentialExtensionOutputs(credential),
        expectedChallengeDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
      },
      authority: { kind: 'email_otp', emailOtpRegistrationProof: emailAuthority.proof },
      existingFactorSecret,
      walletAuthMethodId: intentResponse.intent.targetWalletAuthMethodId,
      providerSubject,
      worker: walletCustodyWorkerTransport(args.context),
    });
    if (
      linked.finalized.walletId !== args.walletId ||
      linked.finalized.authMethod.kind !== 'email_otp' ||
      linked.finalized.authMethod.status !== 'active'
    ) {
      throw new Error('Wallet add-email-code finalize returned a mismatched auth method');
    }
    await persistFinalizedEmailOtpAuthMethodV1({
      walletId: args.walletId,
      walletAuthMethodId: intentResponse.intent.targetWalletAuthMethodId,
      /* R109C adds to the authority the source method already belongs to, so
         the new method's authority is the source claim's — no authority is
         created here, and none is read back from the finalize. */
      walletAuthorityId: sourceClaim.source.walletAuthorityId,
      emailAddress,
      authority: linked.finalized.authority,
    });
    await copyWalletCustodyEcdsaContinuityToAuthMethod({
      walletId: args.walletId,
      sourceWalletAuthMethodId: sourceClaim.source.walletAuthMethodId,
      targetAuthority: await walletAuthAuthorityRef({ authority: linked.finalized.authority }),
    });
    return {
      ok: true,
      walletId: args.walletId,
      emailAddress,
      authMethod: { kind: 'email_otp', status: 'active' },
    };
  } finally {
    existingFactorSecret.fill(0);
  }
}

export async function addEmailOtpWalletAuthMethod(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId | string;
  readonly emailAddress: string;
  readonly options?: AddEmailOtpHooksOptions;
}): Promise<AddEmailOtpResult> {
  const walletId = walletIdFromString(String(args.walletId || '').trim());
  try {
    const result = await addEmailOtpWalletAuthMethodInternal({
      context: args.context,
      walletId,
      emailAddress: args.emailAddress,
      options: args.options,
    });
    await args.options?.afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    const normalized = toError(error);
    try {
      args.options?.onError?.(normalized);
    } finally {
      await args.options?.afterCall?.(false);
    }
    throw normalized;
  }
}
