import type { PasskeyEnvelopeId, WalletId } from '../utils/domainIds';
import type {
  EmailOtpFactorKekVersion,
  PasskeyCustodyEnvelopeRecord,
  PasskeyPrfKekVersion,
  WalletCustodyEnvelopeFactor,
} from './custodyEnvelope';
import type { PasskeyCustodySecretKind } from './custodySecretBinding';

// One KEK purpose per custody-secret branch. Deriving the purpose from the
// binding kind means a KEK that opens the wallet seed cannot open a lane
// holder share, even under the same credential.
export type PasskeyCustodyKekPurpose = PasskeyCustodySecretKind;

/**
 * The exact HKDF `info` inputs for one envelope's KEK:
 *
 *   factor_kek = HKDF-SHA256(
 *     ikm  = the factor secret (WebAuthn PRF.first, or the Email OTP factor key),
 *     salt = versioned application salt,
 *     info = hash(factor identity, walletId, envelopeId, purpose, version))
 *
 * The factor secret and the salt are not part of this record: the context is
 * public binding data, and only the secure worker ever holds the secret.
 *
 * The factor branch is carried whole rather than flattened, so a passkey
 * context can never be built from an Email OTP envelope's identity — the two
 * factors wrap the same seed but must never derive the same KEK.
 */
export type PasskeyCustodyKekDerivationContext = {
  kind: 'wallet_custody_kek_derivation_context_v2';
  walletId: WalletId;
  envelopeId: PasskeyEnvelopeId;
  factor: WalletCustodyEnvelopeFactor;
  purpose: PasskeyCustodyKekPurpose;
  kekVersion: PasskeyPrfKekVersion | EmailOtpFactorKekVersion;
};

/**
 * Derives the KEK context from a parsed envelope. Callers cannot assemble one
 * field by field, so a KEK is always bound to the factor, wallet, envelope, and
 * custody branch the ciphertext was sealed under.
 */
export function buildPasskeyCustodyKekDerivationContext(
  envelope: PasskeyCustodyEnvelopeRecord,
): PasskeyCustodyKekDerivationContext {
  return {
    kind: 'wallet_custody_kek_derivation_context_v2',
    walletId: envelope.walletId,
    envelopeId: envelope.envelopeId,
    factor: envelope.factor,
    purpose: envelope.binding.kind,
    kekVersion: envelope.factor.kekVersion,
  };
}
