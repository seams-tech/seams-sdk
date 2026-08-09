import type { RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import {
  createWalletAddAuthMethodIntent,
  finalizeWalletAddAuthMethod,
  startWalletAddAuthMethod,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  computeAddAuthMethodIntentDigestB64u,
  walletIdFromString,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import { base64UrlDecode } from '@shared/utils/base64';
import { toError } from '@shared/utils/errors';
import { resolveManagedRuntimeScopeBootstrap } from '@/core/config/managedRuntimeScope';
import { IndexedDBManager, type LocalWalletAuthMethodRecord } from '@/core/indexedDB';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  passkeyCredentialIdB64uFromAuthentication,
  requirePasskeyPrfFirstB64u,
} from './ecdsaBootstrap';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  linkWalletPasskeyCustody,
} from '@/core/signingEngine/walletCustody/passkeyLink';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import { activeWalletOrHostedAppSessionJwt } from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';
import { buildEmailOtpRoutePlan } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';
export type AddPasskeyAuthorization =
  | { readonly kind: 'existing_passkey' }
  | { readonly kind: 'email_otp'; readonly challengeId: string; readonly otpCode: string };

export type AddPasskeyResult = {
  readonly ok: true;
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly authMethod: {
    readonly kind: 'passkey';
    readonly status: 'active';
  };
};

function localPasskeyAuthMethodFromFinalize(args: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
}): LocalWalletAuthMethodRecord & { kind: 'passkey' } {
  const parsedRpId = parseWebAuthnRpId(args.rpId);
  if (!parsedRpId.ok) throw new Error(parsedRpId.error.message);
  const parsedCredentialId = parseWebAuthnCredentialIdB64u(args.credentialIdB64u);
  if (!parsedCredentialId.ok) throw new Error(parsedCredentialId.error.message);
  const credentialPublicKeyB64u = String(args.credentialPublicKeyB64u || '').trim();
  if (!credentialPublicKeyB64u) {
    throw new Error('Wallet add-passkey finalize omitted credential public key');
  }
  if (base64UrlDecode(credentialPublicKeyB64u).byteLength === 0) {
    throw new Error('Wallet add-passkey finalize returned an empty credential public key');
  }
  if (!Number.isSafeInteger(args.counter) || args.counter < 0) {
    throw new Error('Wallet add-passkey finalize returned an invalid credential counter');
  }
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    localStatus: 'synced',
    walletId: args.walletId,
    rpId: parsedRpId.value,
    credentialIdB64u: parsedCredentialId.value,
    credentialPublicKeyB64u,
    counter: args.counter,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

async function persistAddedPasskey(args: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly finalized: Awaited<ReturnType<typeof finalizeWalletAddAuthMethod>>;
}): Promise<AddPasskeyResult> {
  if (
    args.finalized.walletId !== args.walletId ||
    args.finalized.rpId !== args.rpId ||
    args.finalized.authMethod.kind !== 'passkey' ||
    args.finalized.authMethod.status !== 'active'
  ) {
    throw new Error('Wallet add-passkey finalize returned a mismatched auth method');
  }
  const authMethod = localPasskeyAuthMethodFromFinalize({
    walletId: args.finalized.walletId,
    rpId: args.finalized.rpId,
    credentialIdB64u: args.finalized.authMethod.credentialIdB64u,
    credentialPublicKeyB64u: args.finalized.authMethod.credentialPublicKeyB64u,
    counter: args.finalized.authMethod.counter,
  });
  await IndexedDBManager.upsertWalletAuthMethod(authMethod);
  return {
    ok: true,
    walletId: args.finalized.walletId,
    rpId: args.finalized.rpId,
    authMethod: { kind: 'passkey', status: 'active' },
  };
}

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
  const allowCredentials = records
    .map((record) => {
      const id = String(record.credentialId || '').trim();
      if (!id) return null;
      return {
        id,
        type: 'public-key' as const,
        transports: webAuthnTransportsFromRaw(record.transports),
      };
    })
    .filter((record): record is WebAuthnAllowCredential => record !== null);
  if (allowCredentials.length === 0) {
    throw new Error('Wallet add-passkey requires an existing passkey credential');
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

async function addPasskeyWithEmailOtpAuthorization(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly authorization: Extract<AddPasskeyAuthorization, { kind: 'email_otp' }>;
  readonly intentResponse: Awaited<ReturnType<typeof createWalletAddAuthMethodIntent>>;
  readonly defaultSignerSlot: number;
  readonly options?: RegistrationHooksOptions;
}): Promise<AddPasskeyResult> {
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  const appSessionJwt = activeWalletOrHostedAppSessionJwt(relayerUrl, String(args.walletId));
  if (!appSessionJwt) {
    throw new Error('Email OTP add-passkey requires an active wallet-bound app session');
  }
  const worker = args.context.signingEngine.getSignerWorkerContext();
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'login',
    authLane: { kind: 'app_session', jwt: appSessionJwt },
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
  const prepared = await worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'prepareEmailOtpPasskeyCustodyLink',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: String(args.walletId),
        userId: String(args.walletId),
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
        routePlan,
        verification: {
          kind: 'otp',
          challengeId: args.authorization.challengeId,
          otpCode: args.authorization.otpCode,
        },
      },
    },
  });
  let continuationActive = true;
  try {
    const started = await startWalletAddAuthMethod({
      relayerUrl,
      walletId: args.walletId,
      addAuthMethodIntentGrant: args.intentResponse.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: args.intentResponse.addAuthMethodIntentDigestB64u,
      intent: args.intentResponse.intent,
      auth: { kind: 'email_otp', appSessionJwt },
      authority: { kind: 'passkey' },
    });
    if (!started.custodyEnvelope || !started.registration) {
      throw new Error('Email OTP add-passkey start omitted custody envelope or registration options');
    }
    if (
      started.custodyEnvelope.walletId !== args.walletId ||
      started.custodyEnvelope.envelopeId !== prepared.envelopeId ||
      started.custodyEnvelope.envelopeRevision !== prepared.envelopeRevision ||
      started.custodyEnvelope.factor.kind !== 'email_otp' ||
      started.custodyEnvelope.factor.enrollmentId !== prepared.enrollmentId ||
      started.custodyEnvelope.factor.enrollmentSealKeyVersion !==
        prepared.enrollmentSealKeyVersion
    ) {
      throw new Error('Email OTP add-passkey source custody envelope changed');
    }
    const confirmation =
      await args.context.signingEngine.requestRegistrationCredentialConfirmation({
        walletId: String(args.walletId),
        signerSlot: args.defaultSignerSlot,
        confirmerText: args.options?.confirmerText,
        confirmationConfigOverride: args.options?.confirmationConfig,
        registrationOptions: started.registration,
      });
    if (!confirmation.confirmed) {
      throw new Error('Wallet add-passkey registration was cancelled');
    }
    const linked = await worker.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'completeEmailOtpPasskeyCustodyLink',
        timeoutMs: 30_000,
        payload: {
          pendingHandleId: prepared.pendingHandleId,
          existingEnvelope: started.custodyEnvelope,
          registration: {
            kind: started.registration.kind,
            rpId: started.registration.rpId,
          },
          registrationCredential: confirmation.credential,
        },
      },
    });
    continuationActive = false;
    const finalized = await finalizeWalletAddAuthMethod({
      relayerUrl,
      walletId: args.walletId,
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
      webauthnRegistration: linked.registrationCredential,
      custodyEnvelope: linked.custodyEnvelope,
    });
    return await persistAddedPasskey({
      walletId: args.walletId,
      rpId: args.rpId,
      finalized,
    });
  } finally {
    if (continuationActive) {
      await worker
        .requestWorkerOperation({
          kind: 'emailOtp',
          request: {
            type: 'discardEmailOtpPasskeyCustodyLink',
            timeoutMs: 5_000,
            payload: { pendingHandleId: prepared.pendingHandleId },
          },
        })
        .catch(() => undefined);
    }
  }
}

async function addPasskeyWalletAuthMethodInternal(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly authorization: AddPasskeyAuthorization;
  readonly options?: RegistrationHooksOptions;
}): Promise<AddPasskeyResult> {
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) throw new Error('registration.addPasskey requires relayer.url');
  const managedRuntimeScope = resolveManagedRuntimeScopeBootstrap(args.context.configs);
  if (!managedRuntimeScope) {
    throw new Error(
      'registration.addPasskey requires registration.publishableKey and registration.projectEnvironmentId',
    );
  }

  const intentResponse = await createWalletAddAuthMethodIntent({
    relayerUrl,
    walletId: args.walletId,
    request: {
      walletId: args.walletId,
      rpId: args.rpId,
      authMethod: { kind: 'passkey', rpId: args.rpId },
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
    intentResponse.intent.authMethod.kind !== 'passkey' ||
    intentResponse.intent.authMethod.rpId !== args.rpId
  ) {
    throw new Error('Add-auth-method intent identity changed');
  }

  const profile = await IndexedDBManager.getProfile(String(args.walletId));
  if (
    !profile ||
    !Number.isSafeInteger(profile.defaultSignerSlot) ||
    profile.defaultSignerSlot < 1
  ) {
    throw new Error('Wallet add-passkey requires an initialized wallet profile');
  }
  if (args.authorization.kind === 'email_otp') {
    return await addPasskeyWithEmailOtpAuthorization({
      context: args.context,
      walletId: args.walletId,
      rpId: args.rpId,
      authorization: args.authorization,
      intentResponse,
      defaultSignerSlot: profile.defaultSignerSlot,
      options: args.options,
    });
  }
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
    throw new Error('Wallet add-passkey selected a credential outside the authorized wallet');
  }
  const passkeyPrfFirstB64u = requirePasskeyPrfFirstB64u(
    credential,
    'Wallet add-passkey custody linking',
  );
  const existingFactorSecret = base64UrlDecode(passkeyPrfFirstB64u);
  try {
    const linked = await linkWalletPasskeyCustody({
      relayerUrl,
      walletId: args.walletId,
      addAuthMethodIntentGrant: intentResponse.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
      intent: intentResponse.intent,
      auth: {
        kind: 'webauthn_assertion',
        rpId: args.rpId,
        credential: redactCredentialExtensionOutputs(credential),
        expectedChallengeDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
      },
      existingFactorSecret,
      worker: walletCustodyWorkerTransport(args.context),
      createRegistrationCredential: async (registration) => {
        const confirmation =
          await args.context.signingEngine.requestRegistrationCredentialConfirmation({
            walletId: String(args.walletId),
            signerSlot: profile.defaultSignerSlot,
            confirmerText: args.options?.confirmerText,
            confirmationConfigOverride: args.options?.confirmationConfig,
            registrationOptions: registration,
          });
        if (!confirmation.confirmed) {
          throw new Error('Wallet add-passkey registration was cancelled');
        }
        return confirmation.credential;
      },
    });
    return await persistAddedPasskey({
      walletId: args.walletId,
      rpId: args.rpId,
      finalized: linked.finalized,
    });
  } finally {
    existingFactorSecret.fill(0);
  }
}

export async function addPasskeyWalletAuthMethod(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId | string;
  readonly rpId: string;
  readonly authorization: AddPasskeyAuthorization;
  readonly options?: RegistrationHooksOptions;
}): Promise<AddPasskeyResult> {
  const walletId = walletIdFromString(String(args.walletId || '').trim());
  const parsedRpId = parseWebAuthnRpId(String(args.rpId || '').trim());
  if (!parsedRpId.ok) throw new Error(parsedRpId.error.message);
  try {
    const result = await addPasskeyWalletAuthMethodInternal({
      context: args.context,
      walletId,
      rpId: parsedRpId.value,
      authorization: args.authorization,
      options: args.options,
    });
    await args.options?.afterCall?.(true);
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
