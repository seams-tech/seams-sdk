import bs58 from 'bs58';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildWalletEd25519SignerId,
  type WalletEd25519SignerRecord,
  type WalletEd25519YaoActiveCapabilityRecord,
} from '../../core/WalletStore';

export function implicitNearAccountIdFromEd25519PublicKeyBytes(bytes: readonly number[]): string {
  let encoded = '';
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, '0');
  return encoded;
}

export function ed25519NearPublicKeyFromBytes(bytes: readonly number[]): string {
  return `ed25519:${bs58.encode(Uint8Array.from(bytes))}`;
}

export function buildYaoEd25519WalletSignerRecord(input: {
  readonly walletId: WalletEd25519SignerRecord['walletId'];
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly thresholdSessionId: string;
  readonly signerSlot: number;
  readonly publicKey: string;
  readonly signingWorkerId: string;
  readonly keyVersion: string;
  readonly participantIds: readonly [number, number];
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly activeYaoCapability: WalletEd25519YaoActiveCapabilityRecord;
  readonly now: number;
}): WalletEd25519SignerRecord {
  return {
    version: 'wallet_signer_ed25519_v1',
    walletId: input.walletId,
    signerId: buildWalletEd25519SignerId({
      nearAccountId: input.nearAccountId,
      signerSlot: input.signerSlot,
    }),
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    thresholdSessionId: input.thresholdSessionId,
    signerSlot: input.signerSlot,
    publicKey: input.publicKey,
    signingWorkerId: input.signingWorkerId,
    keyVersion: input.keyVersion,
    recoveryExportCapable: true,
    participantIds: [input.participantIds[0], input.participantIds[1]],
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    runtimePolicyScope: input.runtimePolicyScope,
    activeYaoCapability: input.activeYaoCapability,
    createdAtMs: input.now,
    updatedAtMs: input.now,
  };
}

export function replaceYaoEd25519WalletSignerActiveCapability(input: {
  readonly signer: WalletEd25519SignerRecord;
  readonly activeYaoCapability: WalletEd25519YaoActiveCapabilityRecord;
  readonly now: number;
}): WalletEd25519SignerRecord {
  const signer = input.signer;
  return {
    version: 'wallet_signer_ed25519_v1',
    walletId: signer.walletId,
    signerId: signer.signerId,
    nearAccountId: signer.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    thresholdSessionId: signer.thresholdSessionId,
    signerSlot: signer.signerSlot,
    publicKey: signer.publicKey,
    signingWorkerId: signer.signingWorkerId,
    keyVersion: signer.keyVersion,
    recoveryExportCapable: true,
    participantIds: [signer.participantIds[0], signer.participantIds[1]],
    signingRootId: signer.signingRootId,
    signingRootVersion: signer.signingRootVersion,
    runtimePolicyScope: signer.runtimePolicyScope,
    activeYaoCapability: input.activeYaoCapability,
    createdAtMs: signer.createdAtMs,
    updatedAtMs: input.now,
  };
}
