import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention } from '@/core/types/seams';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  selectedEcdsaLane,
  selectedEd25519Lane,
  type SelectedEcdsaLane,
  type SelectedEd25519Lane,
  type ThresholdEcdsaSessionStoreSource,
  type ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import type { SigningLaneAuthBinding } from '../identity/signingLaneAuthBinding';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmFamilyEcdsaKeyIdentity } from '../identity/evmFamilyEcdsaIdentity';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';
import type {
  SelectedEcdsaSigningSessionPlanningLane,
  SelectedSigningSessionPlanningLane,
  SigningSessionOrigin,
  SigningSessionStorageSource,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
} from './types';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type Ed25519PasskeySigningLaneSource = Exclude<
  ThresholdEd25519SessionStoreSource,
  'email_otp'
>;
export type EcdsaPasskeySigningLaneSource = Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;

type CommonSigningLaneInput = {
  retention?: SigningSessionRetention;
};
type BaseEd25519SigningLaneInput = CommonSigningLaneInput & {
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  walletId: WalletId;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
};
type BaseEcdsaSigningLaneInput = CommonSigningLaneInput & {
  key: EvmFamilyEcdsaKeyIdentity;
  materialActivation: MpcMaterialActivationRef;
  keyHandle: string;
  walletId: WalletId;
  authorization: ActiveEvmFamilyWalletSessionAuthorization;
};
export type NearTransactionSigningLane = SelectedEd25519Lane & SelectedSigningSessionPlanningLane;
export type EcdsaTransactionSigningLane = SelectedEcdsaLane & SelectedSigningSessionPlanningLane;
type OptionalRetention<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane> =
  Omit<TLane, 'retention'> & {
    retention?: SigningSessionRetention;
  };
type BuildSigningLaneInput<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane> =
  OptionalRetention<TLane>;

export type Ed25519PasskeySigningLaneInput = BaseEd25519SigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  storageSource: Ed25519PasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type Ed25519EmailOtpSigningLaneInput = BaseEd25519SigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaPasskeySigningLaneInput = BaseEcdsaSigningLaneInput & {
  chainTarget: ThresholdEcdsaChainTarget;
  storageSource: EcdsaPasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaEmailOtpSigningLaneInput = BaseEcdsaSigningLaneInput & {
  chainTarget: ThresholdEcdsaChainTarget;
  sessionOrigin?: SigningSessionOrigin;
};

type PasskeySigningLaneAuthInput = {
  auth: Extract<SigningLaneAuthBinding, { kind: 'passkey' }>;
};

type EmailOtpSigningLaneAuthInput = {
  auth: Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;
};

export type Ed25519PasskeyTransactionSigningLaneInput = PasskeySigningLaneAuthInput &
  Ed25519PasskeySigningLaneInput;
export type Ed25519EmailOtpTransactionSigningLaneInput = EmailOtpSigningLaneAuthInput &
  Ed25519EmailOtpSigningLaneInput;
export type NearTransactionSigningLaneInput =
  | Ed25519PasskeyTransactionSigningLaneInput
  | Ed25519EmailOtpTransactionSigningLaneInput;

export type EcdsaPasskeyTransactionSigningLaneInput = PasskeySigningLaneAuthInput &
  EcdsaPasskeySigningLaneInput;
export type EcdsaEmailOtpTransactionSigningLaneInput = EmailOtpSigningLaneAuthInput &
  EcdsaEmailOtpSigningLaneInput;
export type EcdsaTransactionSigningLaneInput =
  | EcdsaPasskeyTransactionSigningLaneInput
  | EcdsaEmailOtpTransactionSigningLaneInput;

export function buildEd25519PasskeySigningLane(
  input: PasskeySigningLaneAuthInput & Ed25519PasskeySigningLaneInput,
): NearTransactionSigningLane {
  const selectedLane = selectedEd25519Lane({
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    signerSlot: input.signerSlot,
    auth: input.auth,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    thresholdSessionId: input.thresholdSessionId,
  });
  return buildSigningLane<NearTransactionSigningLane>({
    ...selectedLane,
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    storageSource: input.storageSource,
    sessionOrigin:
      input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
    ...(input.retention ? { retention: input.retention } : {}),
  });
}

export function buildEd25519EmailOtpSigningLane(
  input: EmailOtpSigningLaneAuthInput & Ed25519EmailOtpSigningLaneInput,
): NearTransactionSigningLane {
  const selectedLane = selectedEd25519Lane({
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    signerSlot: input.signerSlot,
    auth: input.auth,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    thresholdSessionId: input.thresholdSessionId,
  });
  return buildSigningLane<NearTransactionSigningLane>({
    ...selectedLane,
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
    ...(input.retention ? { retention: input.retention } : {}),
  });
}

export function buildEcdsaPasskeySigningLane(
  input: PasskeySigningLaneAuthInput & EcdsaPasskeySigningLaneInput,
): EcdsaTransactionSigningLane {
  const selectedLane = selectedEcdsaLane({
    key: input.key,
    materialActivation: input.materialActivation,
    keyHandle: input.keyHandle,
    walletId: input.walletId,
    auth: input.auth,
    authorization: input.authorization,
    chainTarget: input.chainTarget,
  });
  return buildSigningLane<EcdsaTransactionSigningLane>({
    ...selectedLane,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: input.chainTarget.kind,
    storageSource: input.storageSource,
    sessionOrigin:
      input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
    ...(input.retention ? { retention: input.retention } : {}),
  });
}

export function buildEcdsaEmailOtpSigningLane(
  input: EmailOtpSigningLaneAuthInput & EcdsaEmailOtpSigningLaneInput,
): EcdsaTransactionSigningLane {
  const selectedLane = selectedEcdsaLane({
    key: input.key,
    materialActivation: input.materialActivation,
    keyHandle: input.keyHandle,
    walletId: input.walletId,
    auth: input.auth,
    authorization: input.authorization,
    chainTarget: input.chainTarget,
  });
  return buildSigningLane<EcdsaTransactionSigningLane>({
    ...selectedLane,
    keyKind: 'threshold_ecdsa_secp256k1',
    chainFamily: input.chainTarget.kind,
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
    ...(input.retention ? { retention: input.retention } : {}),
  });
}

export function buildNearTransactionSigningLane(
  input: NearTransactionSigningLaneInput,
): NearTransactionSigningLane {
  if (isEd25519EmailOtpTransactionSigningLaneInput(input)) {
    return buildEd25519EmailOtpSigningLane(input);
  }
  if (isEd25519PasskeyTransactionSigningLaneInput(input)) {
    return buildEd25519PasskeySigningLane(input);
  }
  input satisfies never;
  throw new Error('[SigningSession] unsupported NEAR lane auth');
}

export function buildTempoTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): EcdsaTransactionSigningLane {
  if (input.chainTarget.kind !== 'tempo') {
    throw new Error('Tempo ECDSA transaction lane requires a Tempo chain target');
  }
  return buildEcdsaTransactionSigningLane(input);
}

export function buildEvmTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): EcdsaTransactionSigningLane {
  if (input.chainTarget.kind !== 'evm') {
    throw new Error('EVM ECDSA transaction lane requires an EIP-155 chain target');
  }
  return buildEcdsaTransactionSigningLane(input);
}

function buildEcdsaTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): EcdsaTransactionSigningLane {
  if (isEcdsaEmailOtpTransactionSigningLaneInput(input)) {
    return buildEcdsaEmailOtpSigningLane(input);
  }
  if (isEcdsaPasskeyTransactionSigningLaneInput(input)) {
    return buildEcdsaPasskeySigningLane(input);
  }
  input satisfies never;
  throw new Error('[SigningSession] unsupported ECDSA lane auth');
}

function isEd25519PasskeyTransactionSigningLaneInput(
  input: NearTransactionSigningLaneInput,
): input is Ed25519PasskeyTransactionSigningLaneInput {
  return input.auth.kind === 'passkey';
}

function isEd25519EmailOtpTransactionSigningLaneInput(
  input: NearTransactionSigningLaneInput,
): input is Ed25519EmailOtpTransactionSigningLaneInput {
  return input.auth.kind === 'email_otp';
}

function isEcdsaPasskeyTransactionSigningLaneInput(
  input: EcdsaTransactionSigningLaneInput,
): input is EcdsaPasskeyTransactionSigningLaneInput {
  return input.auth.kind === 'passkey';
}

function isEcdsaEmailOtpTransactionSigningLaneInput(
  input: EcdsaTransactionSigningLaneInput,
): input is EcdsaEmailOtpTransactionSigningLaneInput {
  return input.auth.kind === 'email_otp';
}

function buildSigningLane<TLane extends NearTransactionSigningLane | EcdsaTransactionSigningLane>(
  input: BuildSigningLaneInput<TLane>,
): TLane {
  return {
    ...input,
    retention: input.retention || 'session',
  } as TLane;
}

function signingSessionOriginFromStorageSource(
  source: Ed25519PasskeySigningLaneSource | EcdsaPasskeySigningLaneSource,
): SigningSessionOrigin {
  switch (source) {
    case 'login':
      return 'login';
    case 'registration':
      return 'registration';
    case 'add-signer':
      return 'add_signer';
    case 'manual-bootstrap':
      return 'manual_bootstrap';
    case 'manual-connect':
      return 'manual_connect';
    case 'bootstrap':
      return 'bootstrap';
    case 'sealed_restore':
      return 'sealed_restore';
  }
}
