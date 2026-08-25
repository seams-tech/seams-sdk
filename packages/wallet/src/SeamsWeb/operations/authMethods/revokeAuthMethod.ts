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
import {
  computeWalletAuthMethodRevokeOperationFingerprintV1,
  walletIdFromString,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
} from '@shared/utils/domainIds';
import { IndexedDBManager } from '@/core/indexedDB';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { passkeyCredentialIdB64uFromAuthentication } from './passkey/ecdsaBootstrap';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';

import { revokeWalletAuthMethod as revokeWalletAuthMethodRoute } from '@/core/rpcClients/relayer/walletRegistration';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';

export type RevokeAuthMethodResult = {
  readonly ok: true;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authMethod: { readonly kind: string; readonly status: 'revoked' };
};

/**
 * Every local passkey credential except the one being revoked.
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

async function passkeySourceCredentials(args: {
  readonly walletId: WalletId;
  readonly excludeCredentialIdB64u: string | null;
}): Promise<WebAuthnAllowCredential[]> {
  const authenticators = await IndexedDBManager.listProfileAuthenticators(String(args.walletId));
  const allowCredentials: WebAuthnAllowCredential[] = [];
  for (const record of authenticators) {
    const id = String(record.credentialId || '').trim();
    if (!id || id === args.excludeCredentialIdB64u) continue;
    allowCredentials.push({
      id,
      type: 'public-key',
      transports: webAuthnTransportsFromRaw(record.transports),
    });
  }
  return allowCredentials;
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
  if (allowCredentials.length === 0) {
    throw new Error('registration.revokeAuthMethod requires another passkey to authorize with');
  }
  const credential = await args.context.signingEngine.getAuthenticationCredentialsSerialized({
    subjectId: String(args.walletId),
    challengeB64u: String(operationFingerprintDigest),
    allowCredentials,
    includeSecondPrfOutput: false,
  });
  const credentialIdB64u = passkeyCredentialIdB64uFromAuthentication(credential);
  if (!credentialIdB64u || !allowCredentials.some((allowed) => allowed.id === credentialIdB64u)) {
    throw new Error('registration.revokeAuthMethod used a credential outside the wallet');
  }
  const response = await revokeWalletAuthMethodRoute({
    relayerUrl,
    walletId: args.walletId,
    walletAuthMethodId: args.walletAuthMethodId,
    requestedAtMs,
    sourceProof: {
      kind: 'webauthn_assertion',
      rpId: parsedRpId.value,
      credential: redactCredentialExtensionOutputs(credential),
      expectedChallengeDigestB64u: String(operationFingerprintDigest),
    },
  });
  if (!response.ok || response.authMethod.status !== 'revoked') {
    throw new Error('registration.revokeAuthMethod did not revoke the method');
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
