/**
 * Wallet custody envelope boundary for the browser SDK.
 *
 * The records themselves live in `@shared/passkey-custody` because the Gateway
 * envelope store, the wallet iframe, and the secure worker all parse the same
 * shapes. This module is the SDK-facing surface: import envelope types and
 * their branch-specific builders/parsers from here rather than reaching into
 * shared paths directly.
 *
 * The names here track the custody model, not the credential that unwraps it.
 * An envelope holds one wallet custody seed sealed under one *factor* — a
 * passkey or an Email OTP enrolment — and both factors reach the same seed, so
 * nothing in this surface is passkey-specific.
 */
export type {
  Ed25519PublicKeyB64u,
  EmailOtpFactorKekVersion,
  EnvelopeCiphertextB64u,
  EnvelopeNonceB64u,
  EnvelopeRevision,
  KeyCreationSignerSlot,
  PasskeyCustodyEnvelopeLifecycle,
  PasskeyCustodyEnvelopeRecord,
  PasskeyCustodyKekDerivationContext,
  PasskeyCustodyKekPurpose,
  PasskeyCustodySecretBinding,
  PasskeyCustodySecretBindingOfKind,
  PasskeyCustodySecretKind,
  PasskeyDeviceEnvelopeIndexRecord,
  PasskeyPrfKekVersion,
  Secp256k1CompressedPublicKeyB64u,
  WalletCustodyEnvelopeFactor,
  WalletCustodyEnvelopeVersion,
  WalletCustodyFactorKind,
  WalletSeedDerivationScheme,
} from '@shared/passkey-custody';

export {
  EMAIL_OTP_FACTOR_KEK_VERSION_V1,
  PASSKEY_PRF_KEK_VERSION_V1,
  WALLET_CUSTODY_ENVELOPE_VERSION_V2,
  WALLET_SEED_DERIVATION_SCHEME_V1,
  buildActiveEnvelopeLifecycle,
  buildEcdsaLaneHolderShareBinding,
  buildEd25519LaneHolderShareBinding,
  buildEmailOtpEnvelopeFactor,
  buildPasskeyCustodyEnvelopeRecord,
  buildPasskeyCustodyKekDerivationContext,
  buildPasskeyEnvelopeFactor,
  buildRetiredEnvelopeLifecycle,
  buildRevokedEnvelopeLifecycle,
  buildWalletCustodySeedBinding,
  isActivePasskeyCustodyEnvelope,
  isWalletCustodySeedBinding,
  parseEd25519PublicKeyB64u,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parseKeyCreationSignerSlot,
  parsePasskeyCustodyEnvelopeLifecycle,
  parsePasskeyCustodyEnvelopeRecord,
  parsePasskeyCustodySecretBinding,
  parseSecp256k1CompressedPublicKeyB64u,
  parseWalletCustodyEnvelopeFactor,
} from '@shared/passkey-custody';

export type {
  RecoveryCodeLifecycleState,
  WalletRecoveryCodeKekDerivationContext,
  WalletRecoveryEntryKekDerivationContext,
  WalletRecoveryEnvelopeEntry,
  WalletRecoveryEnvelopeSetRecord,
  WalletRecoveryManifestKekWrap,
} from '@shared/wallet-recovery';

export {
  buildWalletCustodySeedRecoveryEntry,
  buildWalletRecoveryEntryKekDerivationContext,
  buildWalletRecoveryEnvelopeSetRecord,
  buildWalletRecoveryManifestKekWrap,
  hasOpenableRecoveryCodeWrap,
  parseWalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
