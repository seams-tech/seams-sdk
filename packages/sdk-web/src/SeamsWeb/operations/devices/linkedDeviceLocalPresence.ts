import { computeLinkedDeviceLocalPresenceChallengeDigestV1 } from '@shared/device-linking/digests';
import type { LinkedDeviceLocalPresenceAssertionV1 } from '@shared/device-linking';
import type { AuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlDecode } from '@shared/utils/base64';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AuthenticatorPort } from '@/core/platform';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  ActiveLinkedDeviceExecutionBundleV1,
  ActiveLinkedDeviceExecutionChildV1,
} from '@/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import type {
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
} from './deviceLinkingPorts';

export type LinkedDevicePresenceAndHolderV1<TAuthorizationResult> = {
  readonly localPresenceAssertion: LinkedDeviceLocalPresenceAssertionV1;
  readonly holderMaterial: DeviceLinkingHolderSigningMaterialHandleV1;
  readonly authorizationResult: TAuthorizationResult;
};

function assertPresenceLifetime(input: {
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly walletSessionExpiresAtMs: number;
}): void {
  if (
    !Number.isSafeInteger(input.issuedAtMs) ||
    !Number.isSafeInteger(input.expiresAtMs) ||
    input.issuedAtMs < 0 ||
    input.issuedAtMs >= input.expiresAtMs ||
    input.expiresAtMs > input.walletSessionExpiresAtMs
  ) {
    throw new Error('linked-device local presence lifetime is invalid');
  }
}

function requireExactCredential(input: {
  readonly credential: WebAuthnAuthenticationCredential;
  readonly returnedCredentialIdB64u: string;
  readonly expectedCredentialIdB64u: string;
  readonly returnedRpId: string;
  readonly expectedRpId: string;
}): WebAuthnAuthenticationCredential {
  if (
    input.returnedCredentialIdB64u !== input.expectedCredentialIdB64u ||
    input.credential.id !== input.expectedCredentialIdB64u ||
    input.credential.rawId !== input.expectedCredentialIdB64u ||
    input.returnedRpId !== input.expectedRpId
  ) {
    throw new Error('linked-device local presence credential binding changed');
  }
  return redactCredentialExtensionOutputs(input.credential);
}

async function requireHolderRecord(input: {
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
}): Promise<LaneSealedHolderRecordV1> {
  const record = await input.repository.get(input.child.holderRecordLookup);
  if (!record) throw new Error('linked-device sealed holder material is unavailable');
  return record;
}

export async function authorizeAndOpenLinkedDeviceHolderV1<TAuthorizationResult>(input: {
  readonly authenticator: AuthenticatorPort;
  readonly holderRepository: LaneSealedHolderMaterialRepositoryV1;
  readonly holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly authorizeBeforeOpen: (
    assertion: LinkedDeviceLocalPresenceAssertionV1,
  ) => Promise<TAuthorizationResult>;
}): Promise<LinkedDevicePresenceAndHolderV1<TAuthorizationResult>> {
  assertPresenceLifetime({
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    walletSessionExpiresAtMs: input.bundle.expiresAtMs,
  });
  if (
    String(input.child.job.enrollmentId) !== String(input.bundle.enrollmentId) ||
    String(input.child.job.walletId) !== String(input.bundle.walletId)
  ) {
    throw new Error('linked-device execution child changed its active parent');
  }
  const credentialIdB64u =
    input.bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u;
  const holderRecord = await requireHolderRecord({
    repository: input.holderRepository,
    child: input.child,
  });
  const challengeDigestB64u = await computeLinkedDeviceLocalPresenceChallengeDigestV1({
    authorizedOperationId: input.authorizedOperationId,
    deviceId: input.bundle.deviceId,
    enrollmentId: input.bundle.enrollmentId,
    credentialIdB64u,
    intentDigestB64u: input.intentDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
  const authentication = await input.authenticator.run({
    kind: 'get_passkey',
    rpId: toRpId(input.bundle.targetPreparation.rpId),
    credentialIdB64u,
    challengeB64u: challengeDigestB64u,
    requirePrfFirst: true,
  });
  if (
    !authentication.ok ||
    authentication.operation !== 'get_passkey' ||
    authentication.requirePrfFirst !== true
  ) {
    throw new Error(
      authentication.ok
        ? 'linked-device local presence returned the wrong authenticator operation'
        : authentication.message,
    );
  }
  const assertion = requireExactCredential({
    credential: authentication.credential,
    returnedCredentialIdB64u: authentication.credentialIdB64u,
    expectedCredentialIdB64u: credentialIdB64u,
    returnedRpId: authentication.rpId,
    expectedRpId: input.bundle.targetPreparation.rpId,
  });
  const factorSecret = base64UrlDecode(authentication.prf.prfFirstB64u);
  if (factorSecret.length !== 32) {
    factorSecret.fill(0);
    throw new Error('linked-device local presence PRF output must be 32 bytes');
  }
  const localPresenceAssertion: LinkedDeviceLocalPresenceAssertionV1 = {
    kind: 'linked_device_local_presence_assertion_v1',
    authorizedOperationId: input.authorizedOperationId,
    deviceId: input.bundle.deviceId,
    enrollmentId: input.bundle.enrollmentId,
    credentialIdB64u,
    intentDigestB64u: input.intentDigestB64u,
    challengeDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    assertion,
  };
  let authorizationResult: TAuthorizationResult;
  let holderMaterial: DeviceLinkingHolderSigningMaterialHandleV1;
  try {
    authorizationResult = await input.authorizeBeforeOpen(localPresenceAssertion);
    holderMaterial = await input.holderMaterial.openPersistedHolderSigningMaterialV1({
      factorSecret: factorSecret.buffer,
      job: input.child.job,
      protocolCommitReceipt: input.child.protocolCommitReceipt,
      materialActivation: input.child.materialActivation,
      holderRecord,
    });
  } finally {
    if (factorSecret.byteLength > 0) factorSecret.fill(0);
  }
  if (holderMaterial.keyFamily !== input.child.keyFamily) {
    await input.holderMaterial.discardHolderSigningMaterialV1({ handle: holderMaterial });
    throw new Error('linked-device holder material changed its active curve');
  }
  return {
    holderMaterial,
    localPresenceAssertion,
    authorizationResult,
  };
}
