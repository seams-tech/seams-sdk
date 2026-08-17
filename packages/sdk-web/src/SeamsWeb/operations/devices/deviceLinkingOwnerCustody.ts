/**
 * Refactor 103 Phase 8 — the custody material Device 1 holds between approving
 * a link and sealing the seed for it.
 *
 * Sealing the wallet custody seed for a linked device needs two owner-only
 * values: the wallet's current custody envelope and the factor secret that
 * opens it. Both are already produced by the approval step. Starting the
 * add-auth-method ceremony returns the envelope, and the assertion that proves
 * owner authority over that ceremony carries PRF.first — the factor secret
 * itself. Nothing here prompts; it captures what the approval prompt already
 * produced.
 *
 * They cannot be used at capture time, because the recipient key they will be
 * sealed to does not exist yet: Device 2 publishes it after the owner approves.
 * So they are held, and the hold is the whole point of this module. A held
 * factor secret is live key material sitting in memory across a network wait,
 * which is only acceptable if it is impossible to leave behind. The hold
 * therefore owns its own zeroization: `sealOnceV1` releases the material into
 * one seal and wipes it whether the seal succeeds or throws, `discardV1` wipes
 * it without sealing, and both are idempotent.
 *
 * Capture verifies that the two values belong together — same wallet, and a
 * factor naming the exact credential that produced the PRF. A mismatch means
 * the secret does not open the envelope, so the pair is refused before the
 * secret is ever decoded.
 */
import { base64UrlDecode } from '@shared/utils/base64';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { WalletId, WebAuthnRpId } from '@shared/utils/domainIds';
import { getPrfFirstB64uFromCredential } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';

/** What a seal receives. Valid only inside the `sealOnceV1` callback. */
export type LinkedDeviceOwnerCustodyMaterialV1 = {
  readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly existingFactorSecret: Uint8Array;
};

export type LinkedDeviceOwnerCustodyHoldV1 = {
  /**
   * Releases the held material into `seal` exactly once.
   *
   * The secret is zeroized as `seal` returns or throws, so it outlives the
   * callback in neither case. A second call is refused rather than handing out
   * a wiped buffer that would seal an all-zero seed.
   */
  readonly sealOnceV1: <T>(
    seal: (material: LinkedDeviceOwnerCustodyMaterialV1) => Promise<T>,
  ) => Promise<T>;
  /** Wipes the material without sealing. Idempotent, and safe after a seal. */
  readonly discardV1: () => void;
};

/**
 * The assertion fields this reads. Narrower than the full credential so the
 * live PRF output is not carried around a wider surface than it needs.
 */
export type LinkedDeviceOwnerCustodyAssertionV1 = {
  readonly rawId: string;
  readonly clientExtensionResults: unknown;
};

export function captureLinkedDeviceOwnerCustodyHoldV1(input: {
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly ownerAssertion: LinkedDeviceOwnerCustodyAssertionV1;
}): LinkedDeviceOwnerCustodyHoldV1 {
  const envelope = input.existingEnvelope;
  // Checked before the secret is decoded: a pair that cannot open is refused
  // without ever materializing key material to clean up.
  if (String(envelope.walletId) !== String(input.walletId)) {
    throw new Error('linked-device owner custody envelope names another wallet');
  }
  const factor = envelope.factor;
  if (
    factor.kind !== 'passkey' ||
    String(factor.credentialIdB64u) !== input.ownerAssertion.rawId ||
    String(factor.rpId) !== String(input.rpId)
  ) {
    throw new Error('linked-device owner custody envelope factor is not the asserted credential');
  }
  const prfFirstB64u = getPrfFirstB64uFromCredential(input.ownerAssertion);
  if (!prfFirstB64u) {
    throw new Error('linked-device owner approval assertion did not return PRF.first');
  }

  const existingFactorSecret = base64UrlDecode(prfFirstB64u);
  let released = false;
  const wipe = (): void => {
    released = true;
    existingFactorSecret.fill(0);
  };
  return {
    sealOnceV1: async (seal) => {
      if (released) throw new Error('linked-device owner custody material was already released');
      released = true;
      try {
        return await seal({ existingEnvelope: envelope, existingFactorSecret });
      } finally {
        existingFactorSecret.fill(0);
      }
    },
    discardV1: wipe,
  };
}
