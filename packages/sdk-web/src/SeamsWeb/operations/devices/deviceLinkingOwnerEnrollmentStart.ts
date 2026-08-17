/**
 * Refactor 103 Phase 8 — Device 1 starts the owner ceremony Device 2 finalizes.
 *
 * Device 2 has no owner authority, so it cannot start an add-auth-method
 * ceremony. Approval is the one owner-authenticated step in the linking flow,
 * so the ceremony is started here, during approval, and travels with the
 * approval that authorizes it.
 *
 * This is the start half only: it creates the intent, proves owner authority
 * freshly against that intent's digest, and starts the ceremony. It never
 * creates a credential — the wallet custody seed reaches Device 2 through the
 * sealed custody transfer instead.
 *
 * That transfer's inputs are both produced right here, so they are captured
 * rather than collected again later. The assertion that authorizes the ceremony
 * carries PRF.first, which is the factor secret, and the ceremony start returns
 * the envelope that secret opens. Capturing them makes this the wallet's only
 * passkey prompt in the whole linking flow. They are held until Device 2
 * publishes a recipient to seal for; see the hold's own contract for how the
 * secret is wiped.
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
import { collectAuthenticationCredentialForChallengeB64u } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  captureLinkedDeviceOwnerCustodyHoldV1,
  type LinkedDeviceOwnerCustodyHoldV1,
} from './deviceLinkingOwnerCustody';

export type DeviceLinkingOwnerEnrollmentStartCollaboratorsV1 = {
  readonly relayerUrl: string;
  readonly rpId: WebAuthnRpId;
  readonly publishableKey: string;
  readonly projectEnvironmentId: string;
  /** Collects the fresh owner assertion that authorizes the ceremony. */
  readonly collectOwnerAssertionV1: (input: {
    readonly walletId: WalletId;
    readonly challengeB64u: string;
  }) => ReturnType<typeof collectAuthenticationCredentialForChallengeB64u>;
};

/** The ceremony the approval carries, and the material Device 1 keeps back. */
export type LinkedDeviceOwnerEnrollmentStartV1 = {
  readonly ceremony: LinkedDeviceOwnerEnrollmentCeremonyV1;
  readonly custodyHold: LinkedDeviceOwnerCustodyHoldV1;
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

  // Proved against this intent's own digest, so the owner is authorizing this
  // ceremony rather than replaying authority granted for another one.
  const credential = await collaborators.collectOwnerAssertionV1({
    walletId: input.walletId,
    challengeB64u: intentResponse.addAuthMethodIntentDigestB64u,
  });

  const started = await startWalletPasskeyAddAuthMethodCeremony({
    relayerUrl: collaborators.relayerUrl,
    walletId: input.walletId,
    addAuthMethodIntentGrant: intentResponse.addAuthMethodIntentGrant,
    addAuthMethodIntentDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
    intent: intentResponse.intent,
    auth: {
      kind: 'webauthn_assertion',
      rpId: collaborators.rpId,
      credential: redactCredentialExtensionOutputs(credential),
      expectedChallengeDigestB64u: intentResponse.addAuthMethodIntentDigestB64u,
    },
  });

  return {
    ceremony: parseLinkedDeviceOwnerEnrollmentCeremonyV1({
      kind: 'linked_device_owner_enrollment_ceremony_v1',
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
      registration: started.registration,
      expiresAtMs: started.expiresAtMs,
    }),
    custodyHold: captureLinkedDeviceOwnerCustodyHoldV1({
      walletId: input.walletId,
      rpId: collaborators.rpId,
      existingEnvelope: started.custodyEnvelope,
      ownerAssertion: credential,
    }),
  };
}
