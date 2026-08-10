import type { WalletRecoverySetRotationWireV1 } from './walletRecoveryEnvelopeSet';
import {
  parseWalletRecoverySetRotationWireV1,
  type WalletRecoveryEnvelopeEntry,
} from './walletRecoveryEnvelopeSet';
import { parseWalletId } from '../utils/domainIds';
import { parseDerivedWalletRecoveryKeyId, WALLET_RECOVERY_CODE_COUNT } from './recoveryCodes';
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

function rotationRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function rotationString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

export function parseWalletRecoverySetRotationWorkerResultV1(
  value: unknown,
): WalletRecoverySetRotationWorkerResultV1 {
  const result = rotationRecord(value, 'rotation worker result');
  if (
    !Array.isArray(result.recoveryManifestKekWraps) ||
    result.recoveryManifestKekWraps.length !== WALLET_RECOVERY_CODE_COUNT
  ) {
    throw new Error(
      `rotation worker result must contain exactly ${WALLET_RECOVERY_CODE_COUNT} recovery wraps`,
    );
  }
  return {
    walletId: rotationString(result.walletId, 'rotation worker walletId'),
    recoveryManifestKekWraps: result.recoveryManifestKekWraps.map((raw, index) => {
      const wrap = rotationRecord(raw, `rotation worker wrap ${index}`);
      return {
        recoveryKeyId: rotationString(wrap.recoveryKeyId, `rotation worker wrap ${index} recoveryKeyId`),
        nonceB64u: rotationString(wrap.nonceB64u, `rotation worker wrap ${index} nonceB64u`),
        ciphertextB64u: rotationString(
          wrap.ciphertextB64u,
          `rotation worker wrap ${index} ciphertextB64u`,
        ),
        aadHashB64u: rotationString(wrap.aadHashB64u, `rotation worker wrap ${index} aadHashB64u`),
      };
    }),
    recoveryEntryNonceB64u: rotationString(
      result.recoveryEntryNonceB64u,
      'rotation worker recoveryEntryNonceB64u',
    ),
    recoveryEntryCiphertextB64u: rotationString(
      result.recoveryEntryCiphertextB64u,
      'rotation worker recoveryEntryCiphertextB64u',
    ),
    recoveryEntryAadHashB64u: rotationString(
      result.recoveryEntryAadHashB64u,
      'rotation worker recoveryEntryAadHashB64u',
    ),
  };
}

/** Projects the Rust/WASM result into the server's full-set wire shape. */
export function walletRecoverySetRotationWireFromWorkerResultV1(
  value: unknown,
): WalletRecoverySetRotationWireV1 {
  const result = parseWalletRecoverySetRotationWorkerResultV1(value);
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
