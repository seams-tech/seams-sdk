import {
  issueWalletRecoveryCodes,
  zeroizeIssuedWalletRecoveryCodes,
  type IssuedWalletRecoveryCodes,
} from '@shared/wallet-recovery/recoveryCodes';
import {
  walletRecoverySetRotationWireFromWorkerResultV1,
  type WalletRecoverySetRotationWorkerResultV1,
} from '@shared/wallet-recovery/walletRecoveryRotation';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { base64UrlEncode } from '@shared/utils/encoders';
import { joinCustodyWireFromEnvelopeRecord } from './joinCustodyWire';
import {
  readWalletRecoverySet,
  rotateWalletRecoverySet,
  type WalletRecoverySetRotateResult,
} from '@/core/rpcClients/relayer/walletRecoveryRotate';

export type WalletRecoveryRotationWorker = {
  rotateRecoverySet(args: {
    readonly custodyJson: string;
    readonly factorSecret: ArrayBuffer;
    readonly recoveryCodesJson: string;
  }): Promise<WalletRecoverySetRotationWorkerResultV1>;
};

export type EmailOtpWalletRecoveryRotationWorker = {
  rotateRecoverySet(args: {
    readonly recoveryCodesJson: string;
  }): Promise<WalletRecoverySetRotationWorkerResultV1>;
};

export type WalletRecoveryRotationOutcome =
  | {
      readonly kind: 'rotated';
      readonly walletId: string;
      readonly recoveryCodes: readonly string[];
      readonly issuedAtMs: number;
      readonly storeVersion: string;
    }
  | Exclude<WalletRecoverySetRotateResult, { readonly kind: 'rotated' }>;

/**
 * Performs one active-factor recovery-set rotation. The worker opens the
 * existing custody envelope and reseals the same seed under a fresh manifest
 * KEK; this coordinator only transports opaque ciphertext and returns the
 * plaintext codes after the server's atomic CAS succeeds.
 */
export async function rotateWalletRecoverySetWithActiveFactorV1(input: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly custodyEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly factorSecret: ArrayBuffer;
  readonly worker: WalletRecoveryRotationWorker;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryRotationOutcome> {
  let issued: IssuedWalletRecoveryCodes | null = issueWalletRecoveryCodes();
  const factorSecret = new Uint8Array(input.factorSecret.slice(0));
  try {
    const current = await readWalletRecoverySet({
      relayUrl: input.relayUrl,
      walletId: input.walletId,
      sessionToken: input.sessionToken,
      ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
    });
    if (current.kind !== 'ready') return current;

    const custody = joinCustodyWireFromEnvelopeRecord(input.custodyEnvelope);
    if (!custody.ok) throw new Error(custody.reason);
    const workerResult = await input.worker.rotateRecoverySet({
      custodyJson: custody.custodyJson,
      factorSecret: factorSecret.buffer.slice(0),
      recoveryCodesJson: JSON.stringify(
        issued.codeBytes.map((bytes) => ({ codeBytesB64u: base64UrlEncode(bytes) })),
      ),
    });
    const replacement = walletRecoverySetRotationWireFromWorkerResultV1(workerResult);
    if (replacement.walletId !== input.walletId) {
      throw new Error('Recovery rotation worker returned a different wallet');
    }
    const rotated = await rotateWalletRecoverySet({
      relayUrl: input.relayUrl,
      walletId: input.walletId,
      sessionToken: input.sessionToken,
      expectedStoreVersion: current.storeVersion,
      replacement,
      ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
    });
    if (rotated.kind !== 'rotated') return rotated;
    return {
      kind: 'rotated',
      walletId: input.walletId,
      recoveryCodes: issued.codes,
      issuedAtMs: rotated.issuedAtMs,
      storeVersion: rotated.storeVersion,
    };
  } finally {
    factorSecret.fill(0);
    if (issued) zeroizeIssuedWalletRecoveryCodes(issued);
    issued = null;
  }
}

export async function rotateWalletRecoverySetWithEmailOtpV1(input: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly worker: EmailOtpWalletRecoveryRotationWorker;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryRotationOutcome> {
  let issued: IssuedWalletRecoveryCodes | null = issueWalletRecoveryCodes();
  try {
    const current = await readWalletRecoverySet({
      relayUrl: input.relayUrl,
      walletId: input.walletId,
      sessionToken: input.sessionToken,
      ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
    });
    if (current.kind !== 'ready') return current;
    const workerResult = await input.worker.rotateRecoverySet({
      recoveryCodesJson: JSON.stringify(
        issued.codeBytes.map((bytes) => ({ codeBytesB64u: base64UrlEncode(bytes) })),
      ),
    });
    const replacement = walletRecoverySetRotationWireFromWorkerResultV1(workerResult);
    if (replacement.walletId !== input.walletId) {
      throw new Error('Recovery rotation worker returned a different wallet');
    }
    const rotated = await rotateWalletRecoverySet({
      relayUrl: input.relayUrl,
      walletId: input.walletId,
      sessionToken: input.sessionToken,
      expectedStoreVersion: current.storeVersion,
      replacement,
      ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
    });
    if (rotated.kind !== 'rotated') return rotated;
    return {
      kind: 'rotated',
      walletId: input.walletId,
      recoveryCodes: issued.codes,
      issuedAtMs: rotated.issuedAtMs,
      storeVersion: rotated.storeVersion,
    };
  } finally {
    if (issued) zeroizeIssuedWalletRecoveryCodes(issued);
    issued = null;
  }
}
