import type { RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import {
  createWalletAddAuthMethodIntent,
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

async function addPasskeyWalletAuthMethodInternal(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId;
  readonly rpId: string;
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
    const finalized = linked.finalized;
    if (
      finalized.walletId !== args.walletId ||
      finalized.rpId !== args.rpId ||
      finalized.authMethod.kind !== 'passkey' ||
      finalized.authMethod.status !== 'active'
    ) {
      throw new Error('Wallet add-passkey finalize returned a mismatched auth method');
    }
    const authMethod = localPasskeyAuthMethodFromFinalize({
      walletId: finalized.walletId,
      rpId: finalized.rpId,
      credentialIdB64u: finalized.authMethod.credentialIdB64u,
      credentialPublicKeyB64u: finalized.authMethod.credentialPublicKeyB64u,
      counter: finalized.authMethod.counter,
    });
    await IndexedDBManager.upsertWalletAuthMethod(authMethod);
    return {
      ok: true,
      walletId: finalized.walletId,
      rpId: finalized.rpId,
      authMethod: { kind: 'passkey', status: 'active' },
    };
  } finally {
    existingFactorSecret.fill(0);
  }
}

export async function addPasskeyWalletAuthMethod(args: {
  readonly context: RegistrationWebContext;
  readonly walletId: WalletId | string;
  readonly rpId: string;
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
