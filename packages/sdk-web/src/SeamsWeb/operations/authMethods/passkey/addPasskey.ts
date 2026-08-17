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
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { base64UrlDecode } from '@shared/utils/base64';
import { toError } from '@shared/utils/errors';
import { resolveManagedRuntimeScopeBootstrap } from '@/core/config/managedRuntimeScope';
import { IndexedDBManager } from '@/core/indexedDB';
import { persistFinalizedPasskeyAuthMethodV1 } from './localPasskeyProjection';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import {
  passkeyCredentialIdB64uFromAuthentication,
  requirePasskeyPrfFirstB64u,
} from './ecdsaBootstrap';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { linkWalletPasskeyCustody } from '@/core/signingEngine/walletCustody/passkeyLink';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
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

export type AddPasskeyHooksOptions = Omit<RegistrationHooksOptions, 'afterCall'> & {
  readonly afterCall?: AfterCall<AddPasskeyResult>;
};

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

async function addPasskeyWalletAuthMethodInternal(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly authorization: AddPasskeyAuthorization;
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
    throw new Error('Wallet add-passkey requires a fresh passkey owner proof');
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
      authorization: args.authorization,
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
