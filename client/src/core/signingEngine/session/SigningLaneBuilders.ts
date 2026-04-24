import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionRetention } from '@/core/types/tatchi';
import type {
  ThresholdEcdsaSessionStoreSource,
  ThresholdEd25519SessionStoreSource,
} from '../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaActivationChain } from '../orchestration/thresholdActivation';
import type {
  BackingMaterialSessionId,
  SigningLaneContext,
  SigningSessionOrigin,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  WalletSigningSessionId,
} from './signingSessionTypes';

export type Ed25519PasskeySigningLaneSource = Exclude<
  ThresholdEd25519SessionStoreSource,
  'email_otp'
>;
export type EcdsaPasskeySigningLaneSource = Exclude<
  ThresholdEcdsaSessionStoreSource,
  'email_otp'
>;

type BaseSigningLaneInput = {
  accountId: AccountId;
  walletSigningSessionId: WalletSigningSessionId;
  backingMaterialSessionId?: BackingMaterialSessionId;
  retention?: SigningSessionRetention;
  activeSignerSlot?: number;
  signingRootId?: string;
  signingRootVersion?: string;
};
type BuildSigningLaneInput = Omit<SigningLaneContext, 'retention'> & {
  retention?: SigningSessionRetention;
};

export type Ed25519PasskeySigningLaneInput = BaseSigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  storageSource: Ed25519PasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type Ed25519EmailOtpSigningLaneInput = BaseSigningLaneInput & {
  thresholdSessionId: ThresholdEd25519SessionId;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaPasskeySigningLaneInput = BaseSigningLaneInput & {
  chainFamily: ThresholdEcdsaActivationChain;
  thresholdSessionId?: ThresholdEcdsaSessionId;
  storageSource: EcdsaPasskeySigningLaneSource;
  sessionOrigin?: SigningSessionOrigin;
};

export type EcdsaEmailOtpSigningLaneInput = BaseSigningLaneInput & {
  chainFamily: ThresholdEcdsaActivationChain;
  thresholdSessionId?: ThresholdEcdsaSessionId;
  sessionOrigin?: SigningSessionOrigin;
};

export type NearTransactionSigningLaneInput =
  | ({ authMethod: 'passkey' } & Ed25519PasskeySigningLaneInput)
  | ({ authMethod: 'email_otp' } & Ed25519EmailOtpSigningLaneInput);

export type EcdsaTransactionSigningLaneInput =
  | ({ authMethod: 'passkey' } & Omit<EcdsaPasskeySigningLaneInput, 'chainFamily'>)
  | ({ authMethod: 'email_otp' } & Omit<EcdsaEmailOtpSigningLaneInput, 'chainFamily'>);

export function buildEd25519PasskeySigningLane(
  input: Ed25519PasskeySigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'passkey',
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    sessionOrigin: input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEd25519EmailOtpSigningLane(
  input: Ed25519EmailOtpSigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'email_otp',
    curve: 'ed25519',
    keyKind: 'threshold_ed25519',
    chainFamily: 'near',
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
  });
}

export function buildEcdsaPasskeySigningLane(
  input: EcdsaPasskeySigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'passkey',
    curve: 'ecdsa',
    keyKind: 'threshold_ecdsa_secp256k1',
    sessionOrigin: input.sessionOrigin || signingSessionOriginFromStorageSource(input.storageSource),
  });
}

export function buildEcdsaEmailOtpSigningLane(
  input: EcdsaEmailOtpSigningLaneInput,
): SigningLaneContext {
  return buildSigningLane({
    ...input,
    authMethod: 'email_otp',
    curve: 'ecdsa',
    keyKind: 'threshold_ecdsa_secp256k1',
    storageSource: 'email_otp',
    sessionOrigin: input.sessionOrigin || 'per_operation',
  });
}

export function buildNearTransactionSigningLane(
  input: NearTransactionSigningLaneInput,
): SigningLaneContext {
  return input.authMethod === 'email_otp'
    ? buildEd25519EmailOtpSigningLane(input)
    : buildEd25519PasskeySigningLane(input);
}

export function buildTempoTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): SigningLaneContext {
  return buildEcdsaTransactionSigningLane({
    ...input,
    chainFamily: 'tempo',
  });
}

export function buildEvmTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput,
): SigningLaneContext {
  return buildEcdsaTransactionSigningLane({
    ...input,
    chainFamily: 'evm',
  });
}

function buildEcdsaTransactionSigningLane(
  input: EcdsaTransactionSigningLaneInput & { chainFamily: ThresholdEcdsaActivationChain },
): SigningLaneContext {
  return input.authMethod === 'email_otp'
    ? buildEcdsaEmailOtpSigningLane(input)
    : buildEcdsaPasskeySigningLane(input);
}

function buildSigningLane(input: BuildSigningLaneInput): SigningLaneContext {
  return {
    ...input,
    retention: input.retention || 'session',
  };
}

function signingSessionOriginFromStorageSource(
  source: Ed25519PasskeySigningLaneSource | EcdsaPasskeySigningLaneSource,
): SigningSessionOrigin {
  switch (source) {
    case 'login':
      return 'login';
    case 'registration':
      return 'registration';
    case 'manual-bootstrap':
      return 'manual_bootstrap';
    case 'manual-connect':
      return 'manual_connect';
    case 'bootstrap':
      return 'bootstrap';
  }
}
