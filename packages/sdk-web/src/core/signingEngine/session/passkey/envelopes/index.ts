/**
 * Passkey custody envelope boundary for the browser SDK.
 *
 * The records themselves live in `@shared/passkey-custody` because the Gateway
 * envelope store, the wallet iframe, and the secure worker all parse the same
 * shapes. This module is the SDK-facing surface: import envelope types and
 * their branch-specific builders/parsers from here rather than reaching into
 * shared paths directly.
 */
export type {
  Ed25519PublicKeyB64u,
  EnvelopeCiphertextB64u,
  EnvelopeNonceB64u,
  EnvelopeRevision,
  KeyCreationSignerSlot,
  PasskeyCustodyEnvelopeLifecycle,
  PasskeyCustodyEnvelopeRecord,
  PasskeyCustodyEnvelopeVersion,
  PasskeyCustodyKekDerivationContext,
  PasskeyCustodyKekPurpose,
  PasskeyCustodySecretBinding,
  PasskeyCustodySecretBindingOfKind,
  PasskeyCustodySecretKind,
  PasskeyDeviceEnvelopeIndexRecord,
  PasskeyPrfKekVersion,
  Secp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody';

export {
  PASSKEY_CUSTODY_ENVELOPE_VERSION_V1,
  PASSKEY_PRF_KEK_VERSION_V1,
  buildActiveEnvelopeLifecycle,
  buildEcdsaClientRootShareBinding,
  buildEcdsaLaneHolderShareBinding,
  buildEd25519LaneHolderShareBinding,
  buildEd25519YaoClientRootBinding,
  buildPasskeyCustodyEnvelopeRecord,
  buildPasskeyCustodyKekDerivationContext,
  buildRetiredEnvelopeLifecycle,
  buildRevokedEnvelopeLifecycle,
  isActivePasskeyCustodyEnvelope,
  parseEd25519PublicKeyB64u,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parseKeyCreationSignerSlot,
  parsePasskeyCustodyEnvelopeLifecycle,
  parsePasskeyCustodyEnvelopeRecord,
  parsePasskeyCustodySecretBinding,
  parseSecp256k1CompressedPublicKeyB64u,
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
  buildWalletRecoveryCodeKekDerivationContext,
  buildWalletRecoveryEntryKekDerivationContext,
  buildWalletRecoveryEnvelopeEntry,
  buildWalletRecoveryEnvelopeSetRecord,
  buildWalletRecoveryManifestKekWrap,
  hasOpenableRecoveryCodeWrap,
  parseWalletRecoveryEnvelopeSetRecord,
} from '@shared/wallet-recovery';
