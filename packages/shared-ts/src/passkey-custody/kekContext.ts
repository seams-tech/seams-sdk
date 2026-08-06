import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';
import type { PasskeyCustodyEnvelopeRecord, PasskeyPrfKekVersion } from './custodyEnvelope';
import type { PasskeyCustodySecretKind } from './custodySecretBinding';

// One KEK purpose per custody-secret branch. Deriving the purpose from the
// binding kind means a KEK that opens an Ed25519 root can never open an ECDSA
// holder share, even under the same credential.
export type PasskeyCustodyKekPurpose = PasskeyCustodySecretKind;

/**
 * The exact HKDF `info` inputs for one envelope's KEK:
 *
 *   passkey_kek = HKDF-SHA256(
 *     ikm  = WebAuthn PRF.first,
 *     salt = versioned application salt,
 *     info = hash(rpId, credentialId, walletId, envelopeId, purpose, version))
 *
 * The PRF output and the salt are not part of this record: the context is
 * public binding data, and only the secure worker ever holds the PRF result.
 */
export type PasskeyCustodyKekDerivationContext = {
  kind: 'passkey_custody_kek_derivation_context_v1';
  walletId: WalletId;
  envelopeId: PasskeyEnvelopeId;
  rpId: WebAuthnRpId;
  credentialIdB64u: WebAuthnCredentialIdB64u;
  purpose: PasskeyCustodyKekPurpose;
  passkeyKekVersion: PasskeyPrfKekVersion;
};

/**
 * Derives the KEK context from a parsed envelope. Callers cannot assemble one
 * field by field, so a KEK is always bound to the credential, relying party,
 * wallet, envelope, and custody branch the ciphertext was sealed under.
 */
export function buildPasskeyCustodyKekDerivationContext(
  envelope: PasskeyCustodyEnvelopeRecord,
): PasskeyCustodyKekDerivationContext {
  return {
    kind: 'passkey_custody_kek_derivation_context_v1',
    walletId: envelope.walletId,
    envelopeId: envelope.envelopeId,
    rpId: envelope.rpId,
    credentialIdB64u: envelope.credentialIdB64u,
    purpose: envelope.binding.kind,
    passkeyKekVersion: envelope.passkeyKekVersion,
  };
}
