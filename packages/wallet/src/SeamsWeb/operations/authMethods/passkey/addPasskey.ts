import type { AfterCall, RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
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
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { base64UrlDecode } from '@shared/utils/base64';
import { toError } from '@shared/utils/errors';
import { resolveManagedRuntimeScopeBootstrap } from '@/core/config/managedRuntimeScope';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  persistAddedCrossFamilyPasskeyV1,
  persistFinalizedPasskeyAuthMethodV1,
} from './localPasskeyProjection';
import {
  passkeyCredentialIdB64uFromAuthentication,
  requirePasskeyPrfFirstB64u,
} from './ecdsaBootstrap';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { linkWalletPasskeyCustody } from '@/core/signingEngine/walletCustody/passkeyLink';
import { resolveAddAuthMethodSourceClaimV1 } from '../addAuthMethodSourceClaim';
import { requestAddAuthMethodEmailOtpChallenge } from '@/core/rpcClients/relayer/walletRegistration';
import { readUnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/walletCustody/unlockedEd25519ExportRootCapability';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { copyWalletCustodyEcdsaContinuityToAuthMethod } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { addAuthMethodSourcePasskeyAllowCredentials } from '../sourcePasskeyProof';
export type AddPasskeyAuthorization =
  | { readonly kind: 'existing_passkey' }
  | { readonly kind: 'email_otp'; readonly challengeId: string; readonly otpCode: string };

export type AddPasskeyResult = {
  readonly ok: true;
  readonly walletId: WalletId;
  readonly rpId: string;
  /** The method this addition created, so a caller can name it afterwards. */
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authMethod: {
    readonly kind: 'passkey';
    readonly status: 'active';
  };
};

export type AddPasskeyHooksOptions = Omit<RegistrationHooksOptions, 'afterCall'> & {
  readonly afterCall?: AfterCall<AddPasskeyResult>;
};

async function persistAddedPasskey(args: {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
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
  await persistFinalizedPasskeyAuthMethodV1({
    walletId: args.finalized.walletId,
    rpId: args.finalized.rpId,
    credentialIdB64u: args.finalized.authMethod.credentialIdB64u,
    credentialPublicKeyB64u: args.finalized.authMethod.credentialPublicKeyB64u,
    counter: args.finalized.authMethod.counter,
  });
  return {
    ok: true,
    walletId: args.finalized.walletId,
    rpId: args.finalized.rpId,
    walletAuthMethodId: args.walletAuthMethodId,
    authMethod: { kind: 'passkey', status: 'active' },
  };
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

async function addPasskeyWalletAuthMethodInternal(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly options?: AddPasskeyHooksOptions;
}): Promise<AddPasskeyResult> {
  const relayerUrl = String(args.context.configs.network.relayer.url || '').trim();
  if (!relayerUrl) throw new Error('registration.addPasskey requires relayer.url');
  const managedRuntimeScope = resolveManagedRuntimeScopeBootstrap(args.context.configs);
  if (!managedRuntimeScope) {
    throw new Error(
      'registration.addPasskey requires registration.publishableKey and registration.projectEnvironmentId',
    );
  }

  /* R109C: the intent names the source it is minted for, so the fresh
     assertion taken over its digest binds the wallet, authority, source
     method, source session, authority state, and the server-allocated target
     method id. */
  const sourceClaim = await resolveAddAuthMethodSourceClaimV1(args.walletId);
  if (sourceClaim.kind !== 'resolved') {
    throw new Error(`Wallet add-passkey requires a selected active source: ${sourceClaim.reason}`);
  }
  const intentResponse = await createWalletAddAuthMethodIntent({
    relayerUrl,
    walletId: args.walletId,
    request: {
      walletId: args.walletId,
      rpId: args.rpId,
      authMethod: { kind: 'passkey', rpId: args.rpId },
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
  /* R109C `email_otp_to_passkey`: the source is the wallet's Email OTP method,
     so the fresh proof is a one-time code taken over this intent's digest
     rather than an assertion. The seed itself is not re-released — the Email
     unlock that opened this session left its factor secret in the worker, and
     the reseal draws from that handle. */
  if (sourceClaim.sourceAuthMethod.kind === 'email_otp') {
    return await addPasskeyFromEmailOtpSource({
      context: args.context,
      walletId: args.walletId,
      rpId: args.rpId,
      relayerUrl,
      profile,
      sourceWalletAuthorityId: sourceClaim.source.walletAuthorityId,
      sourceWalletAuthMethodId: sourceClaim.source.walletAuthMethodId,
      intentResponse,
      ...(args.options ? { options: args.options } : {}),
    });
  }
  const allowCredentials = addAuthMethodSourcePasskeyAllowCredentials(
    sourceClaim.sourceAuthMethod,
  );
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
      sealSource: { kind: 'factor_secret', existingFactorSecret },
      walletAuthMethodId: intentResponse.intent.targetWalletAuthMethodId,
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
      walletAuthMethodId: intentResponse.intent.targetWalletAuthMethodId,
      finalized: linked.finalized,
    });
  } finally {
    existingFactorSecret.fill(0);
  }
}

/**
 * Refactor 109C's `email_otp_to_passkey` branch.
 *
 * The Email OTP method that already unlocks this wallet authorizes adding a
 * passkey. Three things stay exactly as they are in the Passkey-source branch,
 * deliberately: the target method id comes from the same intent, the reseal and
 * finalize run through the same custody link, and the local installation is the
 * same projection. Only the source proof and the seed's door change.
 *
 * The Email source method and its Wallet Session stay selected — nothing here
 * re-selects, revokes, or re-mints them. Adding a way in does not change the
 * way you came in.
 */
async function addPasskeyFromEmailOtpSource(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly relayerUrl: string;
  readonly profile: { readonly defaultSignerSlot: number };
  readonly sourceWalletAuthorityId: WalletAuthorityId;
  readonly sourceWalletAuthMethodId: Parameters<
    typeof copyWalletCustodyEcdsaContinuityToAuthMethod
  >[0]['sourceWalletAuthMethodId'];
  readonly intentResponse: Awaited<ReturnType<typeof createWalletAddAuthMethodIntent>>;
  readonly options?: AddPasskeyHooksOptions;
}): Promise<AddPasskeyResult> {
  /* The seed's door. An Email unlock parked the factor secret with the opened
     handle, so this addition needs no factor release and no second code. A
     wallet without the capability has not unlocked in this session — the
     honest answer is to unlock, not to prompt for another code. */
  const capability = readUnlockedWalletEd25519ExportRootCapabilityV1(String(args.walletId));
  if (!capability) {
    throw new Error('Wallet add-passkey from an Email OTP source requires an unlocked wallet');
  }
  /* The code goes to the address the wallet already trusts, and the server
     binds it to this intent's digest. Requested only after the intent exists,
     so a refused addition sends no mail. */
  const sendSourceCode = async (): Promise<{ challengeId: string; emailHint: string }> =>
    await requestAddAuthMethodEmailOtpChallenge({
      relayerUrl: args.relayerUrl,
      walletId: args.walletId,
      addAuthMethodIntentGrant: args.intentResponse.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: args.intentResponse.addAuthMethodIntentDigestB64u,
    });
  const sent = await sendSourceCode();
  const confirmed = await args.context.signingEngine.requestEmailOtpEnrollmentConfirmation({
    walletId: String(args.walletId),
    emailAddress: sent.emailHint || 'your email',
    challengeId: sent.challengeId,
    ...(sent.emailHint ? { emailHint: sent.emailHint } : {}),
    confirmerText: {
      title: 'Enter email code to add a passkey',
      body: 'This one-time code confirms you can add a new passkey to this wallet.',
    },
    ...(args.options?.confirmationConfig
      ? { confirmationConfigOverride: args.options.confirmationConfig }
      : {}),
    onResend: sendSourceCode,
  });
  const linked = await linkWalletPasskeyCustody({
    relayerUrl: args.relayerUrl,
    walletId: args.walletId,
    addAuthMethodIntentGrant: args.intentResponse.addAuthMethodIntentGrant,
    addAuthMethodIntentDigestB64u: args.intentResponse.addAuthMethodIntentDigestB64u,
    intent: args.intentResponse.intent,
    /* The fresh source proof: a one-time code the server verifies against this
       intent's digest, so a code taken for some other operation cannot start
       this ceremony. */
    auth: {
      kind: 'email_otp',
      challengeId: confirmed.challengeId,
      otpCode: confirmed.otpCode,
      expectedChallengeDigestB64u: args.intentResponse.addAuthMethodIntentDigestB64u,
    },
    sealSource: { kind: 'unlocked_capability', capability },
    walletAuthMethodId: args.intentResponse.intent.targetWalletAuthMethodId,
    worker: walletCustodyWorkerTransport(args.context),
    createRegistrationCredential: async (registration) => {
      const confirmation =
        await args.context.signingEngine.requestRegistrationCredentialConfirmation({
          walletId: String(args.walletId),
          signerSlot: args.profile.defaultSignerSlot,
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
  const finalized = linked.finalized;
  if (
    finalized.walletId !== args.walletId ||
    finalized.authMethod.kind !== 'passkey' ||
    finalized.authMethod.status !== 'active'
  ) {
    throw new Error('Wallet add-passkey finalize returned a mismatched auth method');
  }
  /* The full local install, not just the auth-method row. This wallet opened
     with Email OTP, so it has no passkey authenticator and no active V2 passkey
     record — and unlock needs both. Writing only the V1 row leaves a wallet
     that has the method on the server and cannot open with it here. */
  await persistAddedCrossFamilyPasskeyV1({
    walletId: args.walletId,
    walletAuthMethodId: args.intentResponse.intent.targetWalletAuthMethodId,
    walletAuthorityId: args.sourceWalletAuthorityId,
    rpId: String(args.rpId),
    credentialIdB64u: finalized.authMethod.credentialIdB64u,
    credentialPublicKeyB64u: finalized.authMethod.credentialPublicKeyB64u,
    counter: finalized.authMethod.counter,
    signerSlot: args.profile.defaultSignerSlot,
    credential: {
      id: finalized.authMethod.credentialIdB64u,
      rawId: finalized.authMethod.credentialIdB64u,
    },
  });
  await copyWalletCustodyEcdsaContinuityToAuthMethod({
    walletId: args.walletId,
    walletAuthorityId: args.sourceWalletAuthorityId,
    sourceWalletAuthMethodId: args.sourceWalletAuthMethodId,
    targetAuthority: await walletAuthAuthorityRef({ authority: finalized.authority }),
  });
  return {
    ok: true,
    walletId: args.walletId,
    rpId: String(args.rpId),
    walletAuthMethodId: args.intentResponse.intent.targetWalletAuthMethodId,
    authMethod: { kind: 'passkey', status: 'active' },
  };
}

export async function addPasskeyWalletAuthMethod(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId | string;
  readonly rpId: string;
  readonly options?: AddPasskeyHooksOptions;
}): Promise<AddPasskeyResult> {
  const walletId = walletIdFromString(String(args.walletId || '').trim());
  const parsedRpId = parseWebAuthnRpId(String(args.rpId || '').trim());
  if (!parsedRpId.ok) throw new Error(parsedRpId.error.message);
  try {
    const result = await addPasskeyWalletAuthMethodInternal({
      context: args.context,
      walletId,
      rpId: parsedRpId.value,
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
