import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type {
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  SigningGrantId,
} from '../operationState/types';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';

export type WarmSessionPersistenceResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

export type EmailOtpWarmSessionMaterial =
  | {
      kind: 'inline';
      clientSecretB64u: string;
      workerSessionId?: never;
    }
  | {
      kind: 'worker_handle';
      workerSessionId: string;
      clientSecretB64u?: never;
    };

export type PasskeyEcdsaWarmSessionMaterial = {
  kind: 'ecdsa_prf_first';
  passkeyPrfFirstB64u: string;
  transport: WarmSessionSealTransportInput;
};

export type PasskeyEd25519WarmSessionMaterial = {
  kind: 'ed25519_prf_first';
  prfFirstB64u: string;
  transport: WarmSessionSealTransportInput;
};

type BaseEmailOtpReadyPersistInput = {
  authMethod: 'email_otp';
  walletId: WalletId;
  signingGrantId: SigningGrantId;
  credentialIdB64u?: never;
  passkeyPrfSealMaterial?: never;
};

type BasePasskeyReadyPersistInput = {
  authMethod: 'passkey';
  walletId: WalletId;
  signingGrantId: SigningGrantId;
  credentialIdB64u: string;
  emailOtpAuthContext?: never;
  material?: never;
};

export type PasskeyReadyPersistenceSource =
  | {
      kind: 'fresh_webauthn';
      credentialIdB64u: string;
      restoredThresholdSessionId?: never;
    }
  | {
      kind: 'session_reconnect';
      restoredThresholdSessionId: ThresholdEcdsaSessionId | ThresholdEd25519SessionId;
      credentialIdB64u?: never;
    };

export type EmailOtpEcdsaReadyPersistInput = BaseEmailOtpReadyPersistInput & {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  material: EmailOtpWarmSessionMaterial;
  accountId?: never;
};

export type EmailOtpEd25519ReadyPersistInput = BaseEmailOtpReadyPersistInput & {
  curve: 'ed25519';
  accountId: AccountId;
  thresholdSessionId: ThresholdEd25519SessionId;
  material: EmailOtpWarmSessionMaterial;
  chainTarget?: never;
  emailOtpAuthContext?: never;
};

export type PasskeyEcdsaReadyPersistInput = Omit<
  BasePasskeyReadyPersistInput,
  'credentialIdB64u'
> & {
  curve: 'ecdsa';
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  persistenceSource: PasskeyReadyPersistenceSource;
  passkeyPrfSealMaterial: PasskeyEcdsaWarmSessionMaterial;
  accountId?: never;
};

export type PasskeyEd25519ReadyPersistInput = BasePasskeyReadyPersistInput & {
  curve: 'ed25519';
  accountId: AccountId;
  thresholdSessionId: ThresholdEd25519SessionId;
  passkeyPrfSealMaterial: PasskeyEd25519WarmSessionMaterial;
  chainTarget?: never;
};

export interface EmailOtpWarmSessionPersistencePort {
  persistEcdsaReady(
    input: EmailOtpEcdsaReadyPersistInput,
  ): Promise<WarmSessionPersistenceResult>;
  persistEd25519Ready(
    input: EmailOtpEd25519ReadyPersistInput,
  ): Promise<WarmSessionPersistenceResult>;
}

export interface PasskeyWarmSessionPersistencePort {
  persistEcdsaReady(input: PasskeyEcdsaReadyPersistInput): Promise<WarmSessionPersistenceResult>;
  persistEd25519Ready(input: PasskeyEd25519ReadyPersistInput): Promise<WarmSessionPersistenceResult>;
}
