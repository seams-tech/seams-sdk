import type { WalletRecoverySetRotationWireV1 } from './walletRecoveryEnvelopeSet';
import {
  parseWalletRecoverySetRotationWireV1,
  type WalletRecoveryEnvelopeEntry,
} from './walletRecoveryEnvelopeSet';
import { parseWalletId } from '../utils/domainIds';
import { parseDerivedWalletRecoveryKeyId } from './recoveryCodes';
import {
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
} from '../passkey-custody';

/** Opaque result emitted by the custody WASM after an active factor opens it. */
export type WalletRecoverySetRotationWorkerResultV1 = {
  readonly walletId: string;
  readonly recoveryManifestKekWraps: readonly {
    readonly recoveryKeyId: string;
    readonly nonceB64u: string;
    readonly ciphertextB64u: string;
    readonly aadHashB64u: string;
  }[];
  readonly recoveryEntryNonceB64u: string;
  readonly recoveryEntryCiphertextB64u: string;
  readonly recoveryEntryAadHashB64u: string;
};

/** Projects the Rust/WASM result into the server's full-set wire shape. */
export function walletRecoverySetRotationWireFromWorkerResultV1(
  result: WalletRecoverySetRotationWorkerResultV1,
): WalletRecoverySetRotationWireV1 {
  const walletId = parseWalletId(result.walletId);
  if (!walletId.ok) throw new Error(`rotation worker wallet id is invalid: ${walletId.error.message}`);
  const entry: WalletRecoveryEnvelopeEntry = {
    custodySecretKind: 'wallet_custody_seed_v1',
    nonceB64u: parseEnvelopeNonceB64u(result.recoveryEntryNonceB64u, 'rotation.entry.nonceB64u'),
    wrappedCustodySecretB64u: parseEnvelopeCiphertextB64u(
      result.recoveryEntryCiphertextB64u,
      'rotation.entry.wrappedCustodySecretB64u',
    ),
    aadHashB64u: parseDigestField(result.recoveryEntryAadHashB64u, 'rotation.entry.aadHashB64u'),
  };
  const raw = {
    walletId: walletId.value,
    manifestKekWraps: result.recoveryManifestKekWraps.map((wrap) => ({
      recoveryKeyId: parseDerivedWalletRecoveryKeyId(wrap.recoveryKeyId, 'rotation.recoveryKeyId'),
      nonceB64u: parseEnvelopeNonceB64u(wrap.nonceB64u, 'rotation.wrap.nonceB64u'),
      ciphertextB64u: parseEnvelopeCiphertextB64u(
        wrap.ciphertextB64u,
        'rotation.wrap.ciphertextB64u',
      ),
      aadHashB64u: parseDigestField(wrap.aadHashB64u, 'rotation.wrap.aadHashB64u'),
    })),
    entries: [entry],
  };
  return parseWalletRecoverySetRotationWireV1(raw, {
    expectedWalletId: walletId.value,
    label: 'rotation.workerResult',
  });
}
