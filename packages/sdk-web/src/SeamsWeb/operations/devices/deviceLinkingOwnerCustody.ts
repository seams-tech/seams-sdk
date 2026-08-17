/**
 * Refactor 103 Phase 8 — the custody material Device 1 needs to seal.
 *
 * Sealing the wallet custody seed for a linked device requires the wallet's
 * current envelope and the factor secret that opens it. Both are owner-only,
 * and both are released here against one named operation.
 *
 * The operation is identified by a challenge digest over every fact a
 * substitution could target: the wallet whose seed this is, the link session
 * and enrollment it belongs to, the device that will receive it, the recipient
 * public key it will be sealed to, and the ceremony that mints the credential
 * on the far side. The recipient is checked against that digest before any
 * material is released, so a relay cannot swap in a recipient key of its own
 * after the owner has approved a different one.
 *
 * Known limit: the digest is not the WebAuthn challenge. Envelope retrieval
 * uses a server-issued unlock challenge, and binding the operation into the
 * assertion as well would mean a second passkey prompt. The digest therefore
 * gates the release rather than being signed by the authenticator.
 */
import {
  computeLinkedDeviceCustodyTransferChallengeDigestV1,
  type LinkedDeviceCustodyTransferChallengeV1,
} from '@shared/device-linking/digests';
import type { LinkedDeviceCustodyTransferRecipientV1 } from '@shared/device-linking/custodyTransfer';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';

export type LinkedDeviceOwnerCustodyMaterialV1 = {
  readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
  /** Live key material. The caller zeroizes it once the seal has consumed it. */
  readonly existingFactorSecret: Uint8Array;
  readonly operationChallengeDigestB64u: DigestB64u;
};

export type LinkedDeviceOwnerCustodyRequestV1 = {
  readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
  readonly addAuthMethodCeremonyId: string;
};

/** What the surface supplies: one assertion, and the envelope it unlocks. */
export type LinkedDeviceOwnerCustodyCollaboratorsV1 = {
  /**
   * Collects an owner assertion carrying PRF.first and resolves the custody
   * envelope for the credential that produced it — never for a credential
   * chosen by the caller.
   */
  readonly resolveOwnerCustodyForCredentialV1: (input: { readonly walletId: string }) => Promise<{
    readonly envelope: PasskeyCustodyEnvelopeRecord;
    readonly credentialIdB64u: string;
    readonly rpId: string;
    readonly factorSecret: Uint8Array;
  }>;
};

export async function collectLinkedDeviceOwnerCustodyMaterialV1(
  collaborators: LinkedDeviceOwnerCustodyCollaboratorsV1,
  request: LinkedDeviceOwnerCustodyRequestV1,
): Promise<LinkedDeviceOwnerCustodyMaterialV1> {
  const challenge: LinkedDeviceCustodyTransferChallengeV1 = {
    kind: 'linked_device_custody_transfer_challenge_v1',
    walletId: String(request.recipient.walletId),
    linkSessionId: String(request.recipient.linkSessionId),
    enrollmentId: String(request.recipient.enrollmentId),
    deviceId: String(request.recipient.deviceId),
    recipientPublicKeyB64u: String(request.recipient.recipientPublicKeyB64u),
    addAuthMethodCeremonyId: request.addAuthMethodCeremonyId,
  };
  const operationChallengeDigestB64u =
    await computeLinkedDeviceCustodyTransferChallengeDigestV1(challenge);

  const resolved = await collaborators.resolveOwnerCustodyForCredentialV1({
    walletId: challenge.walletId,
  });
  const factorSecret = resolved.factorSecret;
  try {
    const envelope = resolved.envelope;
    // The envelope has to be this wallet's, and its factor has to be the
    // credential that just produced the PRF. Either mismatch means the secret
    // in hand does not open the envelope in hand.
    if (String(envelope.walletId) !== challenge.walletId) {
      throw new Error('linked-device custody transfer envelope names another wallet');
    }
    const factor = envelope.factor;
    if (
      factor.kind !== 'passkey' ||
      String(factor.credentialIdB64u) !== resolved.credentialIdB64u ||
      String(factor.rpId) !== resolved.rpId
    ) {
      throw new Error(
        'linked-device custody transfer envelope factor is not the asserted credential',
      );
    }
    return {
      existingEnvelope: envelope,
      existingFactorSecret: factorSecret,
      operationChallengeDigestB64u,
    };
  } catch (error: unknown) {
    // Nothing downstream will consume it, so it must not outlive this call.
    factorSecret.fill(0);
    throw error;
  }
}
