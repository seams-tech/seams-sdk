import { alphabetizeStringify } from '@shared/utils/digests';
import { parseWalletRecoveryOperationId } from '@shared/utils/domainIds';
import {
  pendingWalletRecoveryCommitIdentityMatches,
  type PendingWalletRecoveryCommitV1,
  type PendingWalletRecoveryEncryptedMaterialV1,
} from '@/core/indexedDB/pendingWalletRecoveryCommit';
import {
  durablePayloadIdentityTarget,
  isDurablePasskeyPayload,
  parseWalletRecoveryDurablePayload,
  validateWalletRecoveryDurablePayloadBindings,
  walletRecoveryDurablePayloadWireForm,
  WALLET_RECOVERY_DURABLE_PAYLOAD_VERSION,
  type WalletRecoveryDurablePayloadV1,
} from './walletRecoveryDurablePayload';

export {
  durableEmailEnrollmentReference,
  isDurablePasskeyPayload,
  walletRecoveryDurablePayloadFromOperation,
} from './walletRecoveryDurablePayload';
export type {
  WalletRecoveryDurableEmailOtpPayload,
  WalletRecoveryDurableOperationInput,
  WalletRecoveryDurablePasskeyPayload,
  WalletRecoveryDurablePayloadV1,
  WalletRecoveryEmailOtpEnrollment,
} from './walletRecoveryDurablePayload';

type WalletRecoveryCommittedProjection = Extract<
  PendingWalletRecoveryCommitV1,
  { readonly stage: 'server_promoted' }
>['projection'];
type PendingWalletRecoveryCommitBase = Omit<
  Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'awaiting_server_promotion' }>,
  'stage' | 'projection'
>;

const WALLET_RECOVERY_DURABLE_PAYLOAD_AAD_KIND = 'pending_wallet_recovery_commit_v1' as const;
const WALLET_RECOVERY_DURABLE_AES_GCM_IV_BYTES = 12;

type WalletRecoveryDurableAadInput = {
  readonly recoveryOperationId: string;
  readonly walletId: string;
  readonly reservationId: string;
  readonly targetDeviceId: string;
  readonly targetAuthorityId: string;
  readonly targetWalletAuthMethodId: string;
  readonly target: PendingWalletRecoveryCommitV1['target'];
};

function walletRecoveryDurableAad(input: WalletRecoveryDurableAadInput): Uint8Array {
  return new TextEncoder().encode(
    alphabetizeStringify({
      kind: WALLET_RECOVERY_DURABLE_PAYLOAD_AAD_KIND,
      version: WALLET_RECOVERY_DURABLE_PAYLOAD_VERSION,
      ...input,
    }),
  );
}

function durablePayloadAad(payload: WalletRecoveryDurablePayloadV1): Uint8Array {
  return walletRecoveryDurableAad({
    recoveryOperationId: payload.recoveryOperationId,
    walletId: payload.walletId,
    reservationId: payload.reservationId,
    targetDeviceId: payload.targetDeviceId,
    targetAuthorityId: payload.targetAuthorityId,
    targetWalletAuthMethodId: payload.targetWalletAuthMethodId,
    target: durablePayloadIdentityTarget(payload),
  });
}

export async function encryptWalletRecoveryDurablePayload(
  payload: WalletRecoveryDurablePayloadV1,
): Promise<PendingWalletRecoveryEncryptedMaterialV1> {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  if (!(key instanceof CryptoKey)) throw new Error('wallet recovery durable key generation failed');
  const iv = crypto.getRandomValues(new Uint8Array(WALLET_RECOVERY_DURABLE_AES_GCM_IV_BYTES));
  /* The parsed payload is enriched with manifest-derived facts the decrypt
     parser rejects; only the validated wire projection round-trips. */
  const plaintext = new TextEncoder().encode(
    JSON.stringify(walletRecoveryDurablePayloadWireForm(payload)),
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: durablePayloadAad(payload) },
      key,
      plaintext,
    ),
  );
  return {
    kind: 'wallet_recovery_encrypted_material_v1',
    key,
    iv,
    ciphertext,
  };
}

export async function decryptWalletRecoveryDurablePayload(
  record: PendingWalletRecoveryCommitV1,
): Promise<WalletRecoveryDurablePayloadV1> {
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: record.localMaterial.iv,
      additionalData: durablePayloadAadForPendingRecord(record),
    },
    record.localMaterial.key,
    record.localMaterial.ciphertext,
  );
  const payload = parseWalletRecoveryDurablePayload(
    JSON.parse(new TextDecoder().decode(plaintext)) as unknown,
  );
  await validateWalletRecoveryDurablePayloadBindings(payload);
  if (!pendingRecordMatchesDurablePayload(record, payload)) {
    throw new Error('wallet recovery durable payload identity does not match its journal');
  }
  return payload;
}

function durablePayloadAadForPendingRecord(record: PendingWalletRecoveryCommitV1): Uint8Array {
  return walletRecoveryDurableAad({
    recoveryOperationId: record.recoveryOperationId,
    walletId: record.walletId,
    reservationId: record.reservationId,
    targetDeviceId: record.targetDeviceId,
    targetAuthorityId: record.targetAuthorityId,
    targetWalletAuthMethodId: record.targetWalletAuthMethodId,
    target: record.target,
  });
}

export function requireWalletRecoveryOperationId(value: string) {
  const parsed = parseWalletRecoveryOperationId(value);
  if (!parsed.ok) throw new Error('wallet recovery operation id is invalid');
  return parsed.value;
}

function pendingRecordMatchesDurablePayload(
  record: PendingWalletRecoveryCommitV1,
  payload: WalletRecoveryDurablePayloadV1,
): boolean {
  const common = {
    kind: 'pending_wallet_recovery_commit_v1' as const,
    version: 1 as const,
    recoveryOperationId: requireWalletRecoveryOperationId(payload.recoveryOperationId),
    walletId: payload.walletId,
    reservationId: payload.reservationId,
    targetDeviceId: payload.targetDeviceId,
    targetAuthorityId: payload.targetAuthorityId,
    targetWalletAuthMethodId: payload.targetWalletAuthMethodId,
    localMaterial: record.localMaterial,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
  };
  const target = durablePayloadIdentityTarget(payload);
  if (record.stage === 'awaiting_server_promotion') {
    return pendingWalletRecoveryCommitIdentityMatches(record, {
      ...common,
      stage: 'awaiting_server_promotion',
      target,
    });
  }
  switch (target.kind) {
    case 'passkey':
      if (record.projection.kind !== 'passkey') return false;
      return pendingWalletRecoveryCommitIdentityMatches(record, {
        ...common,
        stage: 'server_promoted',
        target,
        projection: record.projection,
      });
    case 'google_email_otp':
      if (record.projection.kind !== 'google_email_otp') return false;
      return pendingWalletRecoveryCommitIdentityMatches(record, {
        ...common,
        stage: 'server_promoted',
        target,
        projection: record.projection,
      });
  }
}

function pendingWalletRecoveryCommonFromPayload(
  payload: WalletRecoveryDurablePayloadV1,
  localMaterial: PendingWalletRecoveryEncryptedMaterialV1,
  createdAtMs: number,
  updatedAtMs: number,
): PendingWalletRecoveryCommitBase {
  return {
    kind: 'pending_wallet_recovery_commit_v1',
    version: 1,
    recoveryOperationId: requireWalletRecoveryOperationId(payload.recoveryOperationId),
    walletId: payload.walletId,
    reservationId: payload.reservationId,
    targetDeviceId: payload.targetDeviceId,
    targetAuthorityId: payload.targetAuthorityId,
    targetWalletAuthMethodId: payload.targetWalletAuthMethodId,
    target: durablePayloadIdentityTarget(payload),
    localMaterial,
    createdAtMs,
    updatedAtMs,
  };
}

export function awaitingPendingWalletRecoveryCommit(
  payload: WalletRecoveryDurablePayloadV1,
  localMaterial: PendingWalletRecoveryEncryptedMaterialV1,
  nowMs = Date.now(),
): Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'awaiting_server_promotion' }> {
  return {
    ...pendingWalletRecoveryCommonFromPayload(payload, localMaterial, nowMs, nowMs),
    stage: 'awaiting_server_promotion',
  };
}

export function promotedPendingWalletRecoveryCommit(
  awaiting: Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'awaiting_server_promotion' }>,
  payload: WalletRecoveryDurablePayloadV1,
  projection: WalletRecoveryCommittedProjection,
  nowMs = Date.now(),
): Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'server_promoted' }> {
  const common = pendingWalletRecoveryCommonFromPayload(
    payload,
    awaiting.localMaterial,
    awaiting.createdAtMs,
    Math.max(nowMs, awaiting.createdAtMs + 1),
  );
  if (isDurablePasskeyPayload(payload)) {
    if (projection.kind !== 'passkey') {
      throw new Error('wallet recovery promotion projection branch changed');
    }
    return {
      ...common,
      stage: 'server_promoted',
      target: durablePayloadIdentityTarget(payload),
      projection,
    };
  }
  if (projection.kind !== 'google_email_otp') {
    throw new Error('wallet recovery promotion projection branch changed');
  }
  return {
    ...common,
    stage: 'server_promoted',
    target: durablePayloadIdentityTarget(payload),
    projection,
  };
}
