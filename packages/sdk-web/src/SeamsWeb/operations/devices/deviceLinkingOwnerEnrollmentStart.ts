/**
 * Refactor 103 Phase 8 — Device 1 starts the owner ceremony Device 2 finalizes.
 *
 * Device 2 has no owner authority, so it cannot start an add-auth-method
 * ceremony. The ceremony is started here, during approval, and travels with
 * the approval that authorizes it.
 *
 * Zero-prompt: owner authority for the start is the active owner Wallet
 * Session, presented as the bearer credential — the same authority that
 * claims the QR session and records the approval. No WebAuthn assertion is
 * collected, no PRF output exists here, and no custody material is held: the
 * wallet custody seed reaches Device 2 through the worker-held unlocked
 * capability established at unlock. The server binds the ceremony to the
 * passkey that minted the session, which is the same factor whose envelope
 * that capability opened.
 *
 * This is the start half only: it creates the intent, verifies the intent
 * digest, and starts the ceremony. It never creates a credential.
 */
import { createWalletAddAuthMethodIntent } from '@/core/rpcClients/relayer/walletRegistration';
import { startWalletPasskeyAddAuthMethodCeremony } from '@/core/signingEngine/walletCustody/passkeyLink';
import {
  computeAddAuthMethodIntentDigestB64u,
  type WalletId,
} from '@shared/utils/registrationIntent';
import type { LinkedDeviceOwnerEnrollmentCeremonyV1 } from '@shared/device-linking/contracts';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import { parseLinkedDeviceOwnerEnrollmentCeremonyV1 } from '@shared/device-linking/parsers';

export type DeviceLinkingOwnerEnrollmentStartCollaboratorsV1 = {
  readonly relayerUrl: string;
  readonly rpId: WebAuthnRpId;
  readonly publishableKey: string;
  readonly projectEnvironmentId: string;
  /**
   * The active owner Wallet Session token. The server resolves the owner and
   * the ceremony's custody factor from it; this module never sees either.
   */
  readonly ownerWalletSessionToken: string;
};

/** The ceremony the approval carries. Nothing else: no hold, no secret. */
export type LinkedDeviceOwnerEnrollmentStartV1 = {
  readonly ceremony: LinkedDeviceOwnerEnrollmentCeremonyV1;
};

export async function startLinkedDeviceOwnerEnrollmentCeremonyV1(
  collaborators: DeviceLinkingOwnerEnrollmentStartCollaboratorsV1,
  input: { readonly walletId: WalletId },
): Promise<LinkedDeviceOwnerEnrollmentStartV1> {
  const intentResponse = await createWalletAddAuthMethodIntent({
    relayerUrl: collaborators.relayerUrl,
    walletId: input.walletId,
    request: {
      walletId: input.walletId,
      rpId: collaborators.rpId,
      authMethod: { kind: 'passkey', rpId: collaborators.rpId },
    },
    auth: {
      publishableKey: collaborators.publishableKey,
      environmentId: collaborators.projectEnvironmentId,
    },
  });
  const intentDigestB64u = await computeAddAuthMethodIntentDigestB64u(intentResponse.intent);
  if (intentDigestB64u !== intentResponse.addAuthMethodIntentDigestB64u) {
    throw new Error('Add-auth-method intent digest mismatch');
  }
  if (
    intentResponse.intent.walletId !== input.walletId ||
    intentResponse.intent.authMethod.kind !== 'passkey' ||
    intentResponse.intent.authMethod.rpId !== collaborators.rpId
  ) {
    throw new Error('Add-auth-method intent identity changed');
  }

  const started = await startWalletPasskeyAddAuthMethodCeremony({
    relayerUrl: collaborators.relayerUrl,
    walletId: input.walletId,
    addAuthMethodIntentGrant: intentResponse.addAuthMethodIntentGrant,
    addAuthMethodIntentDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
    intent: intentResponse.intent,
    auth: {
      kind: 'wallet_session',
      walletSessionToken: collaborators.ownerWalletSessionToken,
    },
  });

  return {
    ceremony: parseLinkedDeviceOwnerEnrollmentCeremonyV1({
      kind: 'linked_device_owner_enrollment_ceremony_v1',
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
      registration: started.registration,
      expiresAtMs: started.expiresAtMs,
    }),
  };
}
