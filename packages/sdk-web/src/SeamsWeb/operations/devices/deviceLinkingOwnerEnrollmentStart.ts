/**
 * Refactor 103 Phase 8 — Device 1 starts the owner ceremony Device 2 finalizes.
 *
 * Device 2 has no owner authority, so it cannot start an add-auth-method
 * ceremony. Approval is the one owner-authenticated step in the linking flow,
 * so the ceremony is started here, during approval, and travels with the
 * approval that authorizes it.
 *
 * This is the start half only. It creates the intent, proves owner authority
 * freshly against that intent's digest, and starts the ceremony. It never
 * creates a credential, never touches the custody envelope the start returns,
 * and never handles a factor secret — the wallet custody seed reaches Device 2
 * through the sealed custody transfer instead.
 */
import {
  createWalletAddAuthMethodIntent,
} from '@/core/rpcClients/relayer/walletRegistration';
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

export async function startLinkedDeviceOwnerEnrollmentCeremonyV1(
  collaborators: DeviceLinkingOwnerEnrollmentStartCollaboratorsV1,
  input: { readonly walletId: WalletId },
): Promise<LinkedDeviceOwnerEnrollmentCeremonyV1> {
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

  return parseLinkedDeviceOwnerEnrollmentCeremonyV1({
    kind: 'linked_device_owner_enrollment_ceremony_v1',
    addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    registration: started.registration,
    expiresAtMs: started.expiresAtMs,
  });
}
