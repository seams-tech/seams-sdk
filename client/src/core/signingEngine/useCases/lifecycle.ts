import type {
  CredentialIdB64u,
  EcdsaProvisioningFailureCode,
  EcdsaProvisioningState,
  EcdsaRoleLocalReadyRecord,
  EmailOtpWorkerIssuedSessionHandle,
  RelayerKeyId,
} from '@/core/platform';
import type { AccountId } from '@/core/types/accountIds';
import type {
  EvmEip155ChainTarget,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletId,
} from '../interfaces/ecdsaChainTarget';
import type {
  NearDelegateActionPayload,
  NearDelegateActionResult,
  NearNep413Payload,
  NearNep413Result,
  NearTransactionsWithActionsPayload,
  NearTransactionsWithActionsResult,
} from '../interfaces/near';
import type { EvmAddress, EvmSigningRequest, Hex } from '../chains/evm/types';
import type { TempoSigningRequest } from '../chains/tempo/types';
import type { EmailOtpAuthSubjectId } from '../session/identity/emailOtpHssIdentity';
import type { RpId } from '../session/identity/evmFamilyEcdsaIdentity';
import type {
  EmailOtpChallengeId,
  SigningOperationId,
  ThresholdSessionId,
  WalletSigningSessionId,
} from '../session/operationState/types';

export type NonEmptyReadonlyArray<T> = readonly [T, ...T[]];
export type PositiveInt = number & { readonly __brand: 'PositiveInt' };
export type UnixTimeMs = number & { readonly __brand: 'UnixTimeMs' };
export type IdempotencyKey = string & { readonly __brand: 'IdempotencyKey' };
export type RestoreAttemptId = string & { readonly __brand: 'RestoreAttemptId' };
export type Ed25519RelayerKeyId = RelayerKeyId & { readonly __curve: 'ed25519' };
export type EcdsaRelayerKeyId = RelayerKeyId & { readonly __curve: 'ecdsa' };
export type WarmSessionRemainingUses = number & {
  readonly __brand: 'WarmSessionRemainingUses';
};

export type UseCaseFailureSource =
  | 'authenticator'
  | 'email_otp'
  | 'signer_crypto'
  | 'storage'
  | 'relayer'
  | 'http'
  | 'budget'
  | 'presign_pool'
  | 'clock'
  | 'random'
  | 'domain';

export type UseCaseFailure<Code extends string> = {
  ok: false;
  code: Code;
  source: UseCaseFailureSource;
  message: string;
  retryable: boolean;
  cause?: unknown;
  value?: never;
};

export function useCaseFailure<Code extends string>(input: {
  code: Code;
  source: UseCaseFailureSource;
  message: string;
  retryable: boolean;
  cause?: unknown;
}): UseCaseFailure<Code> {
  return {
    ok: false,
    code: input.code,
    source: input.source,
    message: input.message,
    retryable: input.retryable,
    ...(input.cause === undefined ? {} : { cause: input.cause }),
  };
}

export function assertNeverUseCase(value: never): never {
  throw new Error(`Unhandled use-case branch: ${String(value)}`);
}

export type LifecycleTransitionTable<StateKind extends string> = {
  readonly [Kind in StateKind]: readonly StateKind[];
};

export type LifecycleTransitionFromTable<T extends Record<string, readonly string[]>> = {
  readonly [From in keyof T & string]: T[From][number] extends infer To
    ? To extends string
      ? { readonly from: From; readonly to: To }
      : never
    : never;
}[keyof T & string];

export type ConfiguredEcdsaTargets = {
  kind: 'configured';
  targets?: never;
};

export type ExplicitEcdsaTargets = {
  kind: 'explicit';
  targets: NonEmptyReadonlyArray<ThresholdEcdsaChainTarget>;
};

export type EcdsaTargetSelection = ConfiguredEcdsaTargets | ExplicitEcdsaTargets;

export type ReadyEd25519Lane = {
  kind: 'ed25519_ready_lane_v1';
  walletId: WalletId;
  rpId: RpId;
  thresholdSessionId: ThresholdSessionId;
  walletSigningSessionId: WalletSigningSessionId;
  relayerKeyId: Ed25519RelayerKeyId;
  remainingUses: WarmSessionRemainingUses;
  expiresAtMs: UnixTimeMs;
  chainTarget?: never;
  readyRecord?: never;
};

export type ReadyEcdsaLane = {
  kind: 'ecdsa_ready_lane_v1';
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  readyRecord: EcdsaRoleLocalReadyRecord;
  relayerKeyId: EcdsaRelayerKeyId;
  thresholdSessionId: ThresholdSessionId;
  walletSigningSessionId: WalletSigningSessionId;
  remainingUses: WarmSessionRemainingUses;
  expiresAtMs: UnixTimeMs;
};

export type ReauthRequiredLane =
  | {
      kind: 'ed25519_reauth_required_v1';
      walletId: WalletId;
      rpId: RpId;
      reason: 'missing_auth' | 'expired_session' | 'stale_sealed_session' | 'malformed_record';
      chainTarget?: never;
    }
  | {
      kind: 'ecdsa_reauth_required_v1';
      walletId: WalletId;
      rpId: RpId;
      chainTarget: ThresholdEcdsaChainTarget;
      reason:
        | 'missing_auth'
        | 'expired_session'
        | 'stale_sealed_session'
        | 'malformed_record'
        | 'missing_ready_material';
    };

export type UseCaseWalletSessionReadiness =
  | {
      kind: 'ready';
      walletId: WalletId;
      ed25519: NonEmptyReadonlyArray<ReadyEd25519Lane>;
      ecdsa: readonly ReadyEcdsaLane[];
      reauthRequired?: never;
    }
  | {
      kind: 'partial';
      walletId: WalletId;
      ed25519: readonly ReadyEd25519Lane[];
      ecdsa: readonly ReadyEcdsaLane[];
      reauthRequired: NonEmptyReadonlyArray<ReauthRequiredLane>;
    }
  | {
      kind: 'reauth_required';
      walletId: WalletId;
      ed25519: readonly [];
      ecdsa: readonly [];
      reauthRequired: NonEmptyReadonlyArray<ReauthRequiredLane>;
    };

export type ReadyWalletSessionReadiness = Extract<UseCaseWalletSessionReadiness, { kind: 'ready' }>;

export type WalletPreferenceWrite = {
  kind: 'wallet_preference_write_v1';
  walletId: WalletId;
  rpId: RpId;
};

export type WalletSignerWrite =
  | {
      kind: 'ed25519_wallet_signer_write_v1';
      lane: ReadyEd25519Lane;
      ecdsa?: never;
    }
  | {
      kind: 'ecdsa_wallet_signer_write_v1';
      lane: ReadyEcdsaLane;
      ed25519?: never;
    };

export type WarmSessionBudgetSpend = {
  kind: 'warm_session_budget_spend_v1';
  walletId: WalletId;
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdSessionId;
  uses: PositiveInt;
  remainingUses: WarmSessionRemainingUses;
};

export type AuthenticatorCreateRequest = {
  kind: 'authenticator_create_request_v1';
  challengeB64u: string;
  userHandleB64u: string;
};

export type AuthenticatorGetRequest = {
  kind: 'authenticator_get_request_v1';
  challengeB64u: string;
  credentialIdB64u: CredentialIdB64u;
};

export type WebAuthnUserHandle = string & { readonly __brand: 'WebAuthnUserHandle' };
export type WebAuthnCredentialId = CredentialIdB64u;
export type EmailAddress = string & { readonly __brand: 'EmailAddress' };
export type EmailOtpCode = string & { readonly __brand: 'EmailOtpCode' };
export type VerifiedAppSessionJwt = string & { readonly __brand: 'VerifiedAppSessionJwt' };

export type RegisterWalletAuth =
  | {
      kind: 'passkey_registration';
      credentialCreation: AuthenticatorCreateRequest;
      userHandle: WebAuthnUserHandle;
      email?: never;
      otp?: never;
      appSession?: never;
    }
  | {
      kind: 'email_otp_registration';
      email: EmailAddress;
      challengeId: EmailOtpChallengeId;
      otp: EmailOtpCode;
      appSession: VerifiedAppSessionJwt;
      credentialCreation?: never;
      userHandle?: never;
    };

export type RegisterWalletInput = {
  walletId: WalletId;
  rpId: RpId;
  auth: RegisterWalletAuth;
  ecdsaTargets: EcdsaTargetSelection;
  idempotencyKey: IdempotencyKey;
};

export type RegistrationReadyLanes = {
  ed25519: ReadyEd25519Lane;
  ecdsa: readonly ReadyEcdsaLane[];
};

export type RegisterWalletSuccess = {
  ok: true;
  walletId: WalletId;
  readiness: ReadyWalletSessionReadiness;
  lanes: RegistrationReadyLanes;
  sealedWrites: NonEmptyReadonlyArray<SigningSessionSealWriteInput>;
  walletPreferenceWrite: WalletPreferenceWrite;
  walletSignerWrites: NonEmptyReadonlyArray<WalletSignerWrite>;
  code?: never;
  message?: never;
  retryable?: never;
};

export type RegisterWalletFailureCode =
  | 'authenticator_failed'
  | 'email_otp_failed'
  | 'wallet_id_collision'
  | 'registration_incomplete'
  | 'stale_identity_mapping'
  | 'signer_crypto_command_failed'
  | 'signer_crypto_invocation_failed'
  | 'relayer_failed'
  | 'storage_failed'
  | 'invalid_state';

export type RegisterWalletResult =
  | RegisterWalletSuccess
  | UseCaseFailure<RegisterWalletFailureCode>;

export type RegisterWalletLifecycleState =
  | ({ kind: 'received_input' } & RegisterWalletInput)
  | {
      kind: 'authenticating';
      walletId: WalletId;
      rpId: RpId;
      auth: RegisterWalletAuth;
      ecdsaTargets: EcdsaTargetSelection;
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'provisioning_ed25519';
      walletId: WalletId;
      rpId: RpId;
      auth: RegisterWalletAuth;
      ecdsaTargets: EcdsaTargetSelection;
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'provisioning_ecdsa';
      walletId: WalletId;
      rpId: RpId;
      auth: RegisterWalletAuth;
      ecdsaTargets: EcdsaTargetSelection;
      ed25519: ReadyEd25519Lane;
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'sealing_sessions';
      walletId: WalletId;
      rpId: RpId;
      lanes: RegistrationReadyLanes;
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'persisting_wallet';
      walletId: WalletId;
      readiness: ReadyWalletSessionReadiness;
      lanes: RegistrationReadyLanes;
      sealedWrites: NonEmptyReadonlyArray<SigningSessionSealWriteInput>;
      idempotencyKey: IdempotencyKey;
    }
  | ({ kind: 'ready' } & RegisterWalletSuccess)
  | ({
      kind: 'failed';
      value?: never;
    } & UseCaseFailure<RegisterWalletFailureCode>);

export type UnlockWalletAuth =
  | {
      kind: 'passkey_unlock';
      credentialId: WebAuthnCredentialId;
      assertionRequest: AuthenticatorGetRequest;
      challengeId?: never;
      otp?: never;
      appSession?: never;
    }
  | {
      kind: 'email_otp_unlock';
      challengeId: EmailOtpChallengeId;
      otp: EmailOtpCode;
      appSession: VerifiedAppSessionJwt;
      credentialId?: never;
      assertionRequest?: never;
    };

export type UnlockWalletInput = {
  walletId: WalletId;
  rpId: RpId;
  auth: UnlockWalletAuth;
  ecdsaTargets: EcdsaTargetSelection;
  idempotencyKey: IdempotencyKey;
};

export type UnlockWalletSuccess = {
  ok: true;
  walletId: WalletId;
  readiness: UseCaseWalletSessionReadiness;
  restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
  provisioned: readonly ReadyEcdsaLane[];
  sealedWrites: NonEmptyReadonlyArray<SigningSessionSealWriteInput>;
  code?: never;
  message?: never;
  retryable?: never;
};

export type UnlockWalletFailureCode =
  | 'missing_auth'
  | 'authenticator_failed'
  | 'email_otp_failed'
  | 'session_expired'
  | 'stale_sealed_session'
  | 'storage_cleanup_failed'
  | 'signer_crypto_command_failed'
  | 'signer_crypto_invocation_failed'
  | 'relayer_failed'
  | 'budget_exhausted'
  | 'invalid_state';

export type UnlockWalletResult = UnlockWalletSuccess | UseCaseFailure<UnlockWalletFailureCode>;

export type UnlockWalletLifecycleState =
  | ({ kind: 'received_input' } & UnlockWalletInput)
  | {
      kind: 'authenticating';
      walletId: WalletId;
      rpId: RpId;
      auth: UnlockWalletAuth;
      ecdsaTargets: EcdsaTargetSelection;
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'restoring_sessions';
      walletId: WalletId;
      rpId: RpId;
      auth: UnlockWalletAuth;
      ecdsaTargets: EcdsaTargetSelection;
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'provisioning_missing_ecdsa';
      walletId: WalletId;
      rpId: RpId;
      restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
      ecdsaTargets: EcdsaTargetSelection;
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'sealing_sessions';
      walletId: WalletId;
      restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
      provisioned: readonly ReadyEcdsaLane[];
      idempotencyKey: IdempotencyKey;
    }
  | {
      kind: 'ready';
      result: UnlockWalletSuccess;
      failed?: never;
    }
  | ({
      kind: 'failed';
      result?: never;
    } & UseCaseFailure<UnlockWalletFailureCode>);

export type SigningSessionActivationPasskeyAuth = {
  kind: 'passkey';
  walletId: WalletId;
  rpId: RpId;
  credentialIdB64u: CredentialIdB64u;
  authSubjectId?: never;
  workerHandle?: never;
};

export type SigningSessionActivationEmailOtpEd25519Auth = {
  kind: 'email_otp';
  walletId: WalletId;
  rpId: RpId;
  authSubjectId: EmailOtpAuthSubjectId;
  workerHandle: Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ed25519_session' }>;
  credentialIdB64u?: never;
};

export type SigningSessionActivationEmailOtpEcdsaAuth = {
  kind: 'email_otp';
  walletId: WalletId;
  rpId: RpId;
  authSubjectId: EmailOtpAuthSubjectId;
  workerHandle: Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ecdsa_bootstrap' }>;
  credentialIdB64u?: never;
};

export type SigningSessionActivationEmailOtpAuth =
  | SigningSessionActivationEmailOtpEd25519Auth
  | SigningSessionActivationEmailOtpEcdsaAuth;

export type SigningSessionActivationAuth =
  | SigningSessionActivationPasskeyAuth
  | SigningSessionActivationEmailOtpAuth;

export type SigningSessionActivationMaterial =
  | {
      kind: 'ed25519_session';
      thresholdSessionId: ThresholdSessionId;
      walletSigningSessionId: WalletSigningSessionId;
      relayerKeyId: Ed25519RelayerKeyId;
      record?: never;
    }
  | {
      kind: 'ecdsa_session';
      thresholdSessionId: ThresholdSessionId;
      walletSigningSessionId: WalletSigningSessionId;
      record: EcdsaRoleLocalReadyRecord;
      relayerKeyId?: never;
    };

export type SigningSessionSealWriteInput =
  | {
      kind: 'passkey_ed25519_seal_write_v1';
      auth: SigningSessionActivationPasskeyAuth;
      material: Extract<SigningSessionActivationMaterial, { kind: 'ed25519_session' }>;
      expiresAtMs: UnixTimeMs;
      remainingUses: WarmSessionRemainingUses;
    }
  | {
      kind: 'passkey_ecdsa_seal_write_v1';
      auth: SigningSessionActivationPasskeyAuth;
      material: Extract<SigningSessionActivationMaterial, { kind: 'ecdsa_session' }>;
      expiresAtMs: UnixTimeMs;
      remainingUses: WarmSessionRemainingUses;
    }
  | {
      kind: 'email_otp_ed25519_seal_write_v1';
      auth: SigningSessionActivationEmailOtpEd25519Auth;
      material: Extract<SigningSessionActivationMaterial, { kind: 'ed25519_session' }>;
      expiresAtMs: UnixTimeMs;
      remainingUses: WarmSessionRemainingUses;
    }
  | {
      kind: 'email_otp_ecdsa_seal_write_v1';
      auth: SigningSessionActivationEmailOtpEcdsaAuth;
      material: Extract<SigningSessionActivationMaterial, { kind: 'ecdsa_session' }>;
      expiresAtMs: UnixTimeMs;
      remainingUses: WarmSessionRemainingUses;
    };

export type ActivateSigningSessionInput = {
  walletId: WalletId;
  rpId: RpId;
  auth: SigningSessionActivationAuth;
  material: NonEmptyReadonlyArray<SigningSessionActivationMaterial>;
};

export type ActivateSigningSessionSuccess = {
  ok: true;
  sealedWrites: readonly SigningSessionSealWriteInput[];
  activatedMaterials: readonly SigningSessionActivationMaterial[];
  code?: never;
  message?: never;
  retryable?: never;
};

export type ActivateSigningSessionFailureCode =
  | 'auth_branch_mismatch'
  | 'material_branch_mismatch'
  | 'session_expired'
  | 'seal_failed'
  | 'storage_failed'
  | 'relayer_failed'
  | 'invalid_state';

export type ActivateSigningSessionResult =
  | ActivateSigningSessionSuccess
  | UseCaseFailure<ActivateSigningSessionFailureCode>;

export type ActivateSigningSessionLifecycleState =
  | ({ kind: 'received_input' } & ActivateSigningSessionInput)
  | {
      kind: 'validating_material';
      walletId: WalletId;
      rpId: RpId;
      auth: SigningSessionActivationAuth;
      material: NonEmptyReadonlyArray<SigningSessionActivationMaterial>;
    }
  | {
      kind: 'writing_seals';
      walletId: WalletId;
      rpId: RpId;
      sealWrites: NonEmptyReadonlyArray<SigningSessionSealWriteInput>;
    }
  | {
      kind: 'activated';
      result: ActivateSigningSessionSuccess;
      failed?: never;
    }
  | ({
      kind: 'failed';
      result?: never;
    } & UseCaseFailure<ActivateSigningSessionFailureCode>);

export type SignEvmFamilyAuthPolicy =
  | { kind: 'warm_session_only'; auth?: never }
  | {
      kind: 'warm_session_or_same_method_step_up';
      auth: SigningSessionActivationAuth;
    };

export type SignEvmFamilyInput =
  | {
      kind: 'evm_transaction';
      operationId: SigningOperationId;
      walletId: WalletId;
      rpId: RpId;
      chainTarget: EvmEip155ChainTarget;
      request: EvmSigningRequest;
      authPolicy: SignEvmFamilyAuthPolicy;
    }
  | {
      kind: 'tempo_transaction';
      operationId: SigningOperationId;
      walletId: WalletId;
      rpId: RpId;
      chainTarget: TempoChainTarget;
      request: TempoSigningRequest;
      authPolicy: SignEvmFamilyAuthPolicy;
    };

export type EvmSignature = {
  kind: 'ecdsa_secp256k1_signature_v1';
  signatureHex: Hex;
};

export type TempoTransactionHash = Hex & { readonly __brand: 'TempoTransactionHash' };

type SignEvmFamilySuccessBase = {
  ok: true;
  walletId: WalletId;
  usedAuth: 'warm_session' | 'same_method_step_up';
  signerLane: ReadyEcdsaLane;
  budgetSpend: WarmSessionBudgetSpend;
  code?: never;
  message?: never;
  retryable?: never;
};

export type SignEvmFamilySuccess =
  | (SignEvmFamilySuccessBase & {
      kind: 'evm_transaction';
      chainTarget: EvmEip155ChainTarget;
      result: {
        kind: 'evm_signature';
        signature: EvmSignature;
        nonceSender: EvmAddress;
      };
    })
  | (SignEvmFamilySuccessBase & {
      kind: 'tempo_transaction';
      chainTarget: TempoChainTarget;
      result: {
        kind: 'tempo_submission';
        signature: EvmSignature;
        nonceSender: EvmAddress;
        transactionHash: TempoTransactionHash;
      };
    });

export type SignEvmFamilyFailureCode =
  | 'missing_ready_ecdsa_material'
  | 'auth_mismatch'
  | 'budget_exhausted'
  | 'relayer_failed'
  | 'signer_failed'
  | 'ambiguous_signer_selection'
  | 'nonce_sender_unavailable'
  | 'chain_target_mismatch'
  | 'invalid_state';

export type SignEvmFamilyResult = SignEvmFamilySuccess | UseCaseFailure<SignEvmFamilyFailureCode>;

export type SignEvmFamilyLifecycleState =
  | {
      kind: 'received_input';
      input: SignEvmFamilyInput;
    }
  | {
      kind: 'resolving_ready_lane';
      input: SignEvmFamilyInput;
    }
  | {
      kind: 'activating_same_method_session';
      input: SignEvmFamilyInput;
      staleLane: ReadyEcdsaLane | ReauthRequiredLane;
    }
  | {
      kind: 'reserving_budget';
      input: SignEvmFamilyInput;
      lane: ReadyEcdsaLane;
    }
  | {
      kind: 'signing';
      input: SignEvmFamilyInput;
      lane: ReadyEcdsaLane;
      budgetSpend: WarmSessionBudgetSpend;
    }
  | {
      kind: 'signed';
      result: SignEvmFamilySuccess;
      failed?: never;
    }
  | ({
      kind: 'failed';
      result?: never;
    } & UseCaseFailure<SignEvmFamilyFailureCode>);

export type NearTransactionDigest = string & { readonly __brand: 'NearTransactionDigest' };
export type Nep413Digest = string & { readonly __brand: 'Nep413Digest' };
export type NearDelegateActionDigest = string & { readonly __brand: 'NearDelegateActionDigest' };
export type Nep413Scope = string & { readonly __brand: 'Nep413Scope' };
export type NearDelegateActionScope = string & { readonly __brand: 'NearDelegateActionScope' };

export type SignNearAuthPolicy =
  | { kind: 'warm_session_only'; auth?: never }
  | {
      kind: 'warm_session_or_same_method_step_up';
      auth: SigningSessionActivationAuth;
    };

export type SignNearInput =
  | {
      kind: 'transactions_with_actions';
      operationId: SigningOperationId;
      walletId: WalletId;
      rpId: RpId;
      accountId: AccountId;
      request: NearTransactionsWithActionsPayload;
      transactionDigests: NonEmptyReadonlyArray<NearTransactionDigest>;
      requiredSignatureUses: PositiveInt;
      authPolicy: SignNearAuthPolicy;
    }
  | {
      kind: 'nep413_message';
      operationId: SigningOperationId;
      walletId: WalletId;
      rpId: RpId;
      accountId: AccountId;
      request: NearNep413Payload;
      digest: Nep413Digest;
      scope: Nep413Scope;
      authPolicy: SignNearAuthPolicy;
    }
  | {
      kind: 'delegate_action';
      operationId: SigningOperationId;
      walletId: WalletId;
      rpId: RpId;
      accountId: AccountId;
      request: NearDelegateActionPayload;
      digest: NearDelegateActionDigest;
      scope: NearDelegateActionScope;
      authPolicy: SignNearAuthPolicy;
    };

type SignNearSuccessBase = {
  ok: true;
  walletId: WalletId;
  accountId: AccountId;
  usedAuth: 'warm_session' | 'same_method_step_up';
  signerLane: ReadyEd25519Lane;
  signingPath: 'presign_pool' | 'two_rtt_fallback' | 'same_method_step_up';
  budgetSpend: WarmSessionBudgetSpend;
  code?: never;
  message?: never;
  retryable?: never;
};

export type SignNearSuccess =
  | (SignNearSuccessBase & {
      kind: 'transactions_with_actions';
      transactionDigests: NonEmptyReadonlyArray<NearTransactionDigest>;
      result: {
        kind: 'near_transactions_with_actions';
        signed: NearTransactionsWithActionsResult;
      };
    })
  | (SignNearSuccessBase & {
      kind: 'nep413_message';
      digest: Nep413Digest;
      scope: Nep413Scope;
      result: {
        kind: 'nep413_message';
        signedMessage: NearNep413Result;
      };
    })
  | (SignNearSuccessBase & {
      kind: 'delegate_action';
      digest: NearDelegateActionDigest;
      scope: NearDelegateActionScope;
      result: {
        kind: 'near_delegate_action';
        signedDelegate: NearDelegateActionResult;
      };
    });

export type SignNearFailureCode =
  | 'missing_ready_ed25519_material'
  | 'budget_exhausted'
  | 'presign_pool_failed'
  | 'relayer_failed'
  | 'digest_mismatch'
  | 'scope_mismatch'
  | 'ambiguous_lane_selection'
  | 'step_up_required'
  | 'dispatch_ambiguous'
  | 'invalid_state';

export type SignNearResult = SignNearSuccess | UseCaseFailure<SignNearFailureCode>;

export type SignNearLifecycleState =
  | {
      kind: 'received_input';
      input: SignNearInput;
    }
  | {
      kind: 'resolving_ready_lane';
      input: SignNearInput;
    }
  | {
      kind: 'validating_request';
      input: SignNearInput;
      lane: ReadyEd25519Lane;
    }
  | {
      kind: 'reserving_budget';
      input: SignNearInput;
      lane: ReadyEd25519Lane;
    }
  | {
      kind: 'signing';
      input: SignNearInput;
      lane: ReadyEd25519Lane;
      budgetSpend: WarmSessionBudgetSpend;
    }
  | {
      kind: 'signed';
      result: SignNearSuccess;
      failed?: never;
    }
  | ({
      kind: 'failed';
      result?: never;
    } & UseCaseFailure<SignNearFailureCode>);

export type ExportAuthorizationScope =
  | {
      kind: 'ed25519_export_scope';
      curve: 'ed25519';
      chain: 'near';
      chainTarget?: never;
    }
  | {
      kind: 'ecdsa_export_scope';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      chain?: never;
    };

export type ExportKeysAuthorization =
  | {
      kind: 'passkey_export_authorized';
      walletId: WalletId;
      rpId: RpId;
      credentialIdB64u: CredentialIdB64u;
      scopes: NonEmptyReadonlyArray<ExportAuthorizationScope>;
      issuedAtMs: UnixTimeMs;
      expiresAtMs: UnixTimeMs;
      authSubjectId?: never;
      challengeId?: never;
    }
  | {
      kind: 'email_otp_export_authorized';
      walletId: WalletId;
      rpId: RpId;
      authSubjectId: EmailOtpAuthSubjectId;
      challengeId: EmailOtpChallengeId;
      scopes: NonEmptyReadonlyArray<ExportAuthorizationScope>;
      issuedAtMs: UnixTimeMs;
      expiresAtMs: UnixTimeMs;
      credentialIdB64u?: never;
    };

export type ExportKeyRequest =
  | {
      kind: 'near_ed25519';
      chainTarget?: never;
    }
  | {
      kind: 'ecdsa_secp256k1';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type ExportKeysInput = {
  walletId: WalletId;
  rpId: RpId;
  requestedKeys: NonEmptyReadonlyArray<ExportKeyRequest>;
  authorization: ExportKeysAuthorization;
};

export type ExportKeyArtifact =
  | {
      kind: 'near_ed25519_export_artifact_v1';
      walletId: WalletId;
      publicKey: string;
      privateKey: string;
      seed: { kind: 'available'; seedB64u: string } | { kind: 'not_available'; seedB64u?: never };
      chainTarget?: never;
      publicFacts?: never;
    }
  | {
      kind: 'ecdsa_secp256k1_export_artifact_v1';
      walletId: WalletId;
      chainTarget: ThresholdEcdsaChainTarget;
      ethereumAddress: `0x${string}`;
      exportPayloadB64u: string;
      publicFacts: EcdsaRoleLocalReadyRecord['publicFacts'];
      privateKey?: never;
      seed?: never;
    };

export type ExportKeysSuccess = {
  ok: true;
  artifacts: readonly ExportKeyArtifact[];
  viewerSessionId: string;
  code?: never;
  message?: never;
  retryable?: never;
  partialArtifacts?: never;
};

export type ExportKeysFailureCode =
  | 'authorization_failed'
  | 'missing_requested_material'
  | 'invalid_ready_state'
  | 'signer_crypto_command_failed'
  | 'signer_crypto_invocation_failed'
  | 'relayer_failed'
  | 'storage_failed'
  | 'invalid_state';

export type ExportKeysResult = ExportKeysSuccess | UseCaseFailure<ExportKeysFailureCode>;

export type ExportKeysLifecycleState =
  | ({ kind: 'received_input' } & ExportKeysInput)
  | {
      kind: 'validating_authorization';
      input: ExportKeysInput;
    }
  | {
      kind: 'loading_material';
      input: ExportKeysInput;
    }
  | {
      kind: 'building_artifacts';
      input: ExportKeysInput;
      material: NonEmptyReadonlyArray<ReadyEd25519Lane | ReadyEcdsaLane>;
    }
  | {
      kind: 'opening_viewer';
      artifacts: NonEmptyReadonlyArray<ExportKeyArtifact>;
    }
  | {
      kind: 'ready';
      result: ExportKeysSuccess;
      failed?: never;
    }
  | ({
      kind: 'failed';
      result?: never;
      partialArtifacts?: never;
    } & UseCaseFailure<ExportKeysFailureCode>);

export type RestorePersistedSessionAuth =
  | {
      kind: 'passkey';
      credentialId: WebAuthnCredentialId;
      authSubjectId?: never;
    }
  | {
      kind: 'email_otp';
      authSubjectId: EmailOtpAuthSubjectId;
      credentialId?: never;
    }
  | {
      kind: 'missing_auth';
      credentialId?: never;
      authSubjectId?: never;
    };

export type RestorePersistedSessionRequest =
  | {
      kind: 'ed25519';
      chainTarget?: never;
    }
  | {
      kind: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type RestorePersistedSessionsInput = {
  restoreAttemptId: RestoreAttemptId;
  walletId: WalletId;
  rpId: RpId;
  auth: RestorePersistedSessionAuth;
  requested: NonEmptyReadonlyArray<RestorePersistedSessionRequest>;
  ecdsaTargets: EcdsaTargetSelection;
  reason: 'page_load' | 'session_status' | 'pre_sign' | 'manual_refresh';
};

export type RestorePersistedSessionCleanup = {
  kind: 'cleanup_required';
  walletId: WalletId;
  rpId: RpId;
  target: RestorePersistedSessionRequest;
  reason: 'malformed_record' | 'expired_record' | 'incompatible_record' | 'seal_mismatch';
};

export type RestorePersistedSessionsSuccess = {
  ok: true;
  walletId: WalletId;
  readiness: UseCaseWalletSessionReadiness;
  restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
  reauthRequired: readonly ReauthRequiredLane[];
  cleanup: readonly RestorePersistedSessionCleanup[];
  code?: never;
  message?: never;
  retryable?: never;
};

export type RestorePersistedSessionsFailureCode =
  | 'stale_persistence'
  | 'unavailable_storage'
  | 'seal_failed'
  | 'incompatible_record'
  | 'malformed_record'
  | 'cleanup_failed'
  | 'invalid_state';

export type RestorePersistedSessionsResult =
  | RestorePersistedSessionsSuccess
  | UseCaseFailure<RestorePersistedSessionsFailureCode>;

export type RestorePersistedSessionsLifecycleState =
  | ({ kind: 'received_input' } & RestorePersistedSessionsInput)
  | {
      kind: 'reading_persistence';
      input: RestorePersistedSessionsInput;
    }
  | {
      kind: 'classifying_material';
      input: RestorePersistedSessionsInput;
      material: readonly (ReadyEd25519Lane | ReadyEcdsaLane | ReauthRequiredLane)[];
    }
  | {
      kind: 'cleaning_stale_records';
      input: RestorePersistedSessionsInput;
      cleanup: NonEmptyReadonlyArray<RestorePersistedSessionCleanup>;
    }
  | {
      kind: 'ready';
      result: RestorePersistedSessionsSuccess;
      failed?: never;
    }
  | ({
      kind: 'failed';
      result?: never;
    } & UseCaseFailure<RestorePersistedSessionsFailureCode>);

export type EcdsaProvisioningStateKind = EcdsaProvisioningState['kind'];
export type RegisterWalletLifecycleStateKind = RegisterWalletLifecycleState['kind'];
export type UnlockWalletLifecycleStateKind = UnlockWalletLifecycleState['kind'];
export type ActivateSigningSessionLifecycleStateKind = ActivateSigningSessionLifecycleState['kind'];
export type SignEvmFamilyLifecycleStateKind = SignEvmFamilyLifecycleState['kind'];
export type SignNearLifecycleStateKind = SignNearLifecycleState['kind'];
export type ExportKeysLifecycleStateKind = ExportKeysLifecycleState['kind'];
export type RestorePersistedSessionsLifecycleStateKind =
  RestorePersistedSessionsLifecycleState['kind'];

export const ecdsaProvisioningAllowedTransitions = {
  needs_secret_source: ['preparing_client_bootstrap', 'failed'],
  preparing_client_bootstrap: ['awaiting_relayer_identity', 'failed'],
  awaiting_relayer_identity: ['finalizing_ready_state', 'failed'],
  finalizing_ready_state: ['persisting_ready_record', 'failed'],
  persisting_ready_record: ['ready', 'failed'],
  ready: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<EcdsaProvisioningStateKind>;

export const registerWalletAllowedTransitions = {
  received_input: ['authenticating', 'failed'],
  authenticating: ['provisioning_ed25519', 'failed'],
  provisioning_ed25519: ['provisioning_ecdsa', 'failed'],
  provisioning_ecdsa: ['sealing_sessions', 'failed'],
  sealing_sessions: ['persisting_wallet', 'failed'],
  persisting_wallet: ['ready', 'failed'],
  ready: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<RegisterWalletLifecycleStateKind>;

export const unlockWalletAllowedTransitions = {
  received_input: ['authenticating', 'failed'],
  authenticating: ['restoring_sessions', 'failed'],
  restoring_sessions: ['provisioning_missing_ecdsa', 'sealing_sessions', 'ready', 'failed'],
  provisioning_missing_ecdsa: ['sealing_sessions', 'failed'],
  sealing_sessions: ['ready', 'failed'],
  ready: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<UnlockWalletLifecycleStateKind>;

export const activateSigningSessionAllowedTransitions = {
  received_input: ['validating_material', 'failed'],
  validating_material: ['writing_seals', 'failed'],
  writing_seals: ['activated', 'failed'],
  activated: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<ActivateSigningSessionLifecycleStateKind>;

export const signEvmFamilyAllowedTransitions = {
  received_input: ['resolving_ready_lane', 'failed'],
  resolving_ready_lane: ['activating_same_method_session', 'reserving_budget', 'failed'],
  activating_same_method_session: ['reserving_budget', 'failed'],
  reserving_budget: ['signing', 'failed'],
  signing: ['signed', 'failed'],
  signed: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<SignEvmFamilyLifecycleStateKind>;

export const signNearAllowedTransitions = {
  received_input: ['resolving_ready_lane', 'failed'],
  resolving_ready_lane: ['validating_request', 'failed'],
  validating_request: ['reserving_budget', 'failed'],
  reserving_budget: ['signing', 'failed'],
  signing: ['signed', 'failed'],
  signed: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<SignNearLifecycleStateKind>;

export const exportKeysAllowedTransitions = {
  received_input: ['validating_authorization', 'failed'],
  validating_authorization: ['loading_material', 'failed'],
  loading_material: ['building_artifacts', 'failed'],
  building_artifacts: ['opening_viewer', 'failed'],
  opening_viewer: ['ready', 'failed'],
  ready: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<ExportKeysLifecycleStateKind>;

export const restorePersistedSessionsAllowedTransitions = {
  received_input: ['reading_persistence', 'failed'],
  reading_persistence: ['classifying_material', 'failed'],
  classifying_material: ['cleaning_stale_records', 'ready', 'failed'],
  cleaning_stale_records: ['ready', 'failed'],
  ready: [],
  failed: [],
} as const satisfies LifecycleTransitionTable<RestorePersistedSessionsLifecycleStateKind>;

export type EcdsaProvisioningTransition = LifecycleTransitionFromTable<
  typeof ecdsaProvisioningAllowedTransitions
>;
export type RegisterWalletTransition = LifecycleTransitionFromTable<
  typeof registerWalletAllowedTransitions
>;
export type UnlockWalletTransition = LifecycleTransitionFromTable<
  typeof unlockWalletAllowedTransitions
>;
export type ActivateSigningSessionTransition = LifecycleTransitionFromTable<
  typeof activateSigningSessionAllowedTransitions
>;
export type SignEvmFamilyTransition = LifecycleTransitionFromTable<
  typeof signEvmFamilyAllowedTransitions
>;
export type SignNearTransition = LifecycleTransitionFromTable<typeof signNearAllowedTransitions>;
export type ExportKeysTransition = LifecycleTransitionFromTable<
  typeof exportKeysAllowedTransitions
>;
export type RestorePersistedSessionsTransition = LifecycleTransitionFromTable<
  typeof restorePersistedSessionsAllowedTransitions
>;

export const ecdsaProvisioningTerminalStates = [
  'ready',
  'failed',
] as const satisfies readonly EcdsaProvisioningStateKind[];
export const registerWalletTerminalStates = [
  'ready',
  'failed',
] as const satisfies readonly RegisterWalletLifecycleStateKind[];
export const unlockWalletTerminalStates = [
  'ready',
  'failed',
] as const satisfies readonly UnlockWalletLifecycleStateKind[];
export const activateSigningSessionTerminalStates = [
  'activated',
  'failed',
] as const satisfies readonly ActivateSigningSessionLifecycleStateKind[];
export const signEvmFamilyTerminalStates = [
  'signed',
  'failed',
] as const satisfies readonly SignEvmFamilyLifecycleStateKind[];
export const signNearTerminalStates = [
  'signed',
  'failed',
] as const satisfies readonly SignNearLifecycleStateKind[];
export const exportKeysTerminalStates = [
  'ready',
  'failed',
] as const satisfies readonly ExportKeysLifecycleStateKind[];
export const restorePersistedSessionsTerminalStates = [
  'ready',
  'failed',
] as const satisfies readonly RestorePersistedSessionsLifecycleStateKind[];

export const ecdsaProvisioningRetryableFailureCodes = [
  'authenticator_failed',
  'signer_crypto_invocation_failed',
  'relayer_failed',
  'storage_failed',
] as const satisfies readonly EcdsaProvisioningFailureCode[];

export const registerWalletRetryableFailureCodes = [
  'authenticator_failed',
  'email_otp_failed',
  'signer_crypto_invocation_failed',
  'relayer_failed',
  'storage_failed',
] as const satisfies readonly RegisterWalletFailureCode[];

export const unlockWalletRetryableFailureCodes = [
  'authenticator_failed',
  'email_otp_failed',
  'signer_crypto_invocation_failed',
  'relayer_failed',
  'storage_cleanup_failed',
] as const satisfies readonly UnlockWalletFailureCode[];

export const activateSigningSessionRetryableFailureCodes = [
  'seal_failed',
  'storage_failed',
  'relayer_failed',
] as const satisfies readonly ActivateSigningSessionFailureCode[];

export const signEvmFamilyRetryableFailureCodes = [
  'relayer_failed',
  'signer_failed',
  'nonce_sender_unavailable',
] as const satisfies readonly SignEvmFamilyFailureCode[];

export const signNearRetryableFailureCodes = [
  'presign_pool_failed',
  'relayer_failed',
] as const satisfies readonly SignNearFailureCode[];

export const exportKeysRetryableFailureCodes = [
  'signer_crypto_invocation_failed',
  'relayer_failed',
  'storage_failed',
] as const satisfies readonly ExportKeysFailureCode[];

export const restorePersistedSessionsRetryableFailureCodes = [
  'unavailable_storage',
  'seal_failed',
  'cleanup_failed',
] as const satisfies readonly RestorePersistedSessionsFailureCode[];

export function assertNeverUseCaseLifecycle(value: never): never {
  throw new Error(`Unhandled use-case lifecycle branch: ${String(value)}`);
}
