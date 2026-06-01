import type {
  ActivateSigningSessionTransition,
  EcdsaProvisioningTransition,
  ExportKeyArtifact,
  ExportKeysResult,
  RegisterWalletAuth,
  RegisterWalletTransition,
  RegistrationReadyLanes,
  RestorePersistedSessionAuth,
  RestorePersistedSessionRequest,
  SignEvmFamilyInput,
  SignNearSuccess,
  SigningSessionActivationAuth,
  SigningSessionActivationEmailOtpEcdsaAuth,
  SigningSessionActivationEmailOtpEd25519Auth,
  SigningSessionActivationMaterial,
  SigningSessionSealWriteInput,
  UnlockWalletAuth,
  UseCaseWalletSessionReadiness,
  ReadyEcdsaLane,
  ReadyEd25519Lane,
  NearTransactionDigest,
  UnixTimeMs,
  WarmSessionRemainingUses,
  WarmSessionBudgetSpend,
  WebAuthnUserHandle,
  EmailAddress,
  EmailOtpCode,
  VerifiedAppSessionJwt,
  RestoreAttemptId,
  RestorePersistedSessionsInput,
  RestorePersistedSessionsTransition,
} from './lifecycle';
import type {
  CredentialIdB64u,
  EcdsaRoleLocalReadyRecord,
  EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import type { AccountId } from '@/core/types/accountIds';
import type {
  EvmEip155ChainTarget,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletId,
} from '../interfaces/ecdsaChainTarget';
import type {
  NearDelegateActionResult,
  NearNep413Result,
  NearTransactionsWithActionsResult,
} from '../interfaces/near';
import type { EvmSigningRequest, Hex } from '../chains/evm/types';
import type { TempoSigningRequest } from '../chains/tempo/types';
import type { EmailOtpAuthSubjectId } from '../session/identity/emailOtpHssIdentity';
import type { RpId } from '../session/identity/evmFamilyEcdsaIdentity';
import type {
  EmailOtpChallengeId,
  SigningOperationId,
  ThresholdSessionId,
  WalletSigningSessionId,
} from '../session/operationState/types';

declare const walletId: WalletId;
declare const rpId: RpId;
declare const accountId: AccountId;
declare const credentialIdB64u: CredentialIdB64u;
declare const emailAddress: EmailAddress;
declare const emailOtpCode: EmailOtpCode;
declare const emailOtpChallengeId: EmailOtpChallengeId;
declare const emailOtpAuthSubjectId: EmailOtpAuthSubjectId;
declare const appSession: VerifiedAppSessionJwt;
declare const userHandle: WebAuthnUserHandle;
declare const thresholdSessionId: ThresholdSessionId;
declare const walletSigningSessionId: WalletSigningSessionId;
declare const operationId: SigningOperationId;
declare const emailOtpEd25519WorkerHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ed25519_session' }
>;
declare const emailOtpEcdsaWorkerHandle: Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;
declare const readyRecord: EcdsaRoleLocalReadyRecord;
declare const readyEd25519Lane: ReadyEd25519Lane;
declare const readyEcdsaLane: ReadyEcdsaLane;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const evmChainTarget: EvmEip155ChainTarget;
declare const tempoChainTarget: TempoChainTarget;
declare const expiresAtMs: UnixTimeMs;
declare const remainingUses: WarmSessionRemainingUses;
declare const evmRequest: EvmSigningRequest;
declare const tempoRequest: TempoSigningRequest;
declare const budgetSpend: WarmSessionBudgetSpend;
declare const nearTransactionDigest: NearTransactionDigest;
declare const nearTransactionsResult: NearTransactionsWithActionsResult;
declare const nearNep413Result: NearNep413Result;
declare const nearDelegateActionResult: NearDelegateActionResult;
declare const hex: Hex;
declare const restoreAttemptId: RestoreAttemptId;

const passkeyRegistration = {
  kind: 'passkey_registration',
  credentialCreation: {
    kind: 'authenticator_create_request_v1',
    challengeB64u: 'challenge',
    userHandleB64u: 'user',
  },
  userHandle,
} satisfies RegisterWalletAuth;
void passkeyRegistration;

const passkeyRegistrationWithEmail = {
  kind: 'passkey_registration',
  credentialCreation: {
    kind: 'authenticator_create_request_v1',
    challengeB64u: 'challenge',
    userHandleB64u: 'user',
  },
  userHandle,
  email: emailAddress,
};
// @ts-expect-error passkey registration cannot carry Email OTP identity fields
passkeyRegistrationWithEmail satisfies RegisterWalletAuth;

const emailOtpRegistrationWithPasskeyCreation = {
  kind: 'email_otp_registration',
  email: emailAddress,
  challengeId: emailOtpChallengeId,
  otp: emailOtpCode,
  appSession,
  credentialCreation: {
    kind: 'authenticator_create_request_v1',
    challengeB64u: 'challenge',
    userHandleB64u: 'user',
  },
};
// @ts-expect-error Email OTP registration cannot carry passkey creation input
emailOtpRegistrationWithPasskeyCreation satisfies RegisterWalletAuth;

const registrationReadyMissingEd25519 = {
  ecdsa: [readyEcdsaLane],
};
// @ts-expect-error registration readiness requires the Ed25519 lane
registrationReadyMissingEd25519 satisfies RegistrationReadyLanes;

const ecdsaLaneMissingTarget = {
  ...readyEcdsaLane,
  chainTarget: undefined,
};
// @ts-expect-error ready ECDSA lanes require an exact chain target
ecdsaLaneMissingTarget satisfies ReadyEcdsaLane;

const passkeyUnlockWithOtp = {
  kind: 'passkey_unlock',
  credentialId: credentialIdB64u,
  assertionRequest: {
    kind: 'authenticator_get_request_v1',
    challengeB64u: 'challenge',
    credentialIdB64u,
  },
  otp: emailOtpCode,
};
// @ts-expect-error passkey unlock cannot carry Email OTP code state
passkeyUnlockWithOtp satisfies UnlockWalletAuth;

const emailOtpUnlockWithCredential = {
  kind: 'email_otp_unlock',
  challengeId: emailOtpChallengeId,
  otp: emailOtpCode,
  appSession,
  credentialId: credentialIdB64u,
};
// @ts-expect-error Email OTP unlock cannot carry passkey credential state
emailOtpUnlockWithCredential satisfies UnlockWalletAuth;

const passkeyActivationAuth = {
  kind: 'passkey',
  walletId,
  rpId,
  credentialIdB64u,
} satisfies SigningSessionActivationAuth;

const emailOtpActivationAuth = {
  kind: 'email_otp',
  walletId,
  rpId,
  authSubjectId: emailOtpAuthSubjectId,
  workerHandle: emailOtpEd25519WorkerHandle,
} satisfies SigningSessionActivationAuth;

const emailOtpEd25519ActivationAuth = {
  kind: 'email_otp',
  walletId,
  rpId,
  authSubjectId: emailOtpAuthSubjectId,
  workerHandle: emailOtpEd25519WorkerHandle,
} satisfies SigningSessionActivationEmailOtpEd25519Auth;

const emailOtpEcdsaActivationAuth = {
  kind: 'email_otp',
  walletId,
  rpId,
  authSubjectId: emailOtpAuthSubjectId,
  workerHandle: emailOtpEcdsaWorkerHandle,
} satisfies SigningSessionActivationEmailOtpEcdsaAuth;

const emailOtpEd25519AuthWithEcdsaHandle = {
  kind: 'email_otp',
  walletId,
  rpId,
  authSubjectId: emailOtpAuthSubjectId,
  workerHandle: emailOtpEcdsaWorkerHandle,
};
// @ts-expect-error Email OTP Ed25519 activation cannot carry an ECDSA worker handle
emailOtpEd25519AuthWithEcdsaHandle satisfies SigningSessionActivationEmailOtpEd25519Auth;

const emailOtpEcdsaAuthWithEd25519Handle = {
  kind: 'email_otp',
  walletId,
  rpId,
  authSubjectId: emailOtpAuthSubjectId,
  workerHandle: emailOtpEd25519WorkerHandle,
};
// @ts-expect-error Email OTP ECDSA activation requires an ECDSA worker handle with chainTarget
emailOtpEcdsaAuthWithEd25519Handle satisfies SigningSessionActivationEmailOtpEcdsaAuth;

const ecdsaActivationMaterial = {
  kind: 'ecdsa_session',
  thresholdSessionId,
  walletSigningSessionId,
  record: readyRecord,
} satisfies SigningSessionActivationMaterial;

const passkeyEcdsaSeal = {
  kind: 'passkey_ecdsa_seal_write_v1',
  auth: passkeyActivationAuth,
  material: ecdsaActivationMaterial,
  expiresAtMs,
  remainingUses,
} satisfies SigningSessionSealWriteInput;

const broadSpreadSealWithWrongAuth = {
  ...passkeyEcdsaSeal,
  auth: emailOtpActivationAuth,
};
// @ts-expect-error broad spreads cannot mix seal-write branch and auth branch
broadSpreadSealWithWrongAuth satisfies SigningSessionSealWriteInput;

const passkeySealWithEmailAuth = {
  kind: 'passkey_ecdsa_seal_write_v1',
  auth: emailOtpActivationAuth,
  material: ecdsaActivationMaterial,
  expiresAtMs,
  remainingUses,
};
// @ts-expect-error passkey seal writes require passkey activation auth
passkeySealWithEmailAuth satisfies SigningSessionSealWriteInput;

const emailOtpEd25519SealWithEcdsaAuth = {
  kind: 'email_otp_ed25519_seal_write_v1',
  auth: emailOtpEcdsaActivationAuth,
  material: {
    kind: 'ed25519_session',
    thresholdSessionId,
    walletSigningSessionId,
    relayerKeyId: readyEd25519Lane.relayerKeyId,
  },
  expiresAtMs,
  remainingUses,
};
// @ts-expect-error Email OTP Ed25519 seal writes require an Ed25519 worker-issued handle
emailOtpEd25519SealWithEcdsaAuth satisfies SigningSessionSealWriteInput;

const emailOtpEcdsaSealWithEd25519Auth = {
  kind: 'email_otp_ecdsa_seal_write_v1',
  auth: emailOtpEd25519ActivationAuth,
  material: ecdsaActivationMaterial,
  expiresAtMs,
  remainingUses,
};
// @ts-expect-error Email OTP ECDSA seal writes require an ECDSA worker-issued handle
emailOtpEcdsaSealWithEd25519Auth satisfies SigningSessionSealWriteInput;

const evmInputWithTempoTarget = {
  kind: 'evm_transaction',
  operationId,
  walletId,
  rpId,
  chainTarget: tempoChainTarget,
  request: evmRequest,
  authPolicy: { kind: 'warm_session_only' },
};
// @ts-expect-error EVM signing input cannot carry a Tempo target
evmInputWithTempoTarget satisfies SignEvmFamilyInput;

const tempoInputWithEvmTarget = {
  kind: 'tempo_transaction',
  operationId,
  walletId,
  rpId,
  chainTarget: evmChainTarget,
  request: tempoRequest,
  authPolicy: { kind: 'warm_session_only' },
};
// @ts-expect-error Tempo signing input cannot carry an EVM target
tempoInputWithEvmTarget satisfies SignEvmFamilyInput;

const transactionSuccessWithNep413Result = {
  ok: true,
  walletId,
  accountId,
  usedAuth: 'warm_session',
  signerLane: readyEd25519Lane,
  signingPath: 'presign_pool',
  budgetSpend,
  kind: 'transactions_with_actions',
  transactionDigests: [nearTransactionDigest],
  result: {
    kind: 'nep413_message',
    signedMessage: nearNep413Result,
  },
};
// @ts-expect-error transaction signing success cannot return an NEP-413 result branch
transactionSuccessWithNep413Result satisfies SignNearSuccess;

const validNearTransactionSuccess = {
  ok: true,
  walletId,
  accountId,
  usedAuth: 'warm_session',
  signerLane: readyEd25519Lane,
  signingPath: 'presign_pool',
  budgetSpend,
  kind: 'transactions_with_actions',
  transactionDigests: [nearTransactionDigest],
  result: {
    kind: 'near_transactions_with_actions',
    signed: nearTransactionsResult,
  },
} satisfies SignNearSuccess;
void validNearTransactionSuccess;
void nearDelegateActionResult;

const ecdsaExportArtifact = {
  kind: 'ecdsa_secp256k1_export_artifact_v1',
  walletId,
  chainTarget,
  ethereumAddress: '0x0000000000000000000000000000000000000001',
  exportPayloadB64u: 'payload',
  publicFacts: readyRecord.publicFacts,
} satisfies ExportKeyArtifact;

const failedExportWithPartialArtifacts = {
  ok: false,
  code: 'storage_failed',
  source: 'storage',
  message: 'failed',
  retryable: true,
  partialArtifacts: [ecdsaExportArtifact],
};
// @ts-expect-error export failures must be all-or-nothing
failedExportWithPartialArtifacts satisfies ExportKeysResult;

const ed25519RestoreWithChainTarget = {
  kind: 'ed25519',
  chainTarget,
};
// @ts-expect-error Ed25519 restore requests cannot carry ECDSA chain targets
ed25519RestoreWithChainTarget satisfies RestorePersistedSessionRequest;

const ecdsaRestoreWithoutChainTarget = {
  kind: 'ecdsa',
};
// @ts-expect-error ECDSA restore requests require a chain target
ecdsaRestoreWithoutChainTarget satisfies RestorePersistedSessionRequest;

const missingAuthWithCredential = {
  kind: 'missing_auth',
  credentialId: credentialIdB64u,
};
// @ts-expect-error missing-auth restore state cannot carry credential identity
missingAuthWithCredential satisfies RestorePersistedSessionAuth;

const restoreInputWithRawSnapshot = {
  restoreAttemptId,
  walletId,
  rpId,
  auth: { kind: 'missing_auth' },
  requested: [{ kind: 'ed25519' }],
  ecdsaTargets: { kind: 'explicit', targets: [chainTarget] },
  reason: 'page_load',
  rawSnapshot: {},
};
// @ts-expect-error restore use-case inputs cannot accept raw or partial persistence snapshots
restoreInputWithRawSnapshot satisfies RestorePersistedSessionsInput;

const restoreInputWithExportReason = {
  restoreAttemptId,
  walletId,
  rpId,
  auth: { kind: 'missing_auth' },
  requested: [{ kind: 'ed25519' }],
  ecdsaTargets: { kind: 'explicit', targets: [chainTarget] },
  reason: 'export',
};
// @ts-expect-error restored transaction sessions cannot be promoted into export authority
restoreInputWithExportReason satisfies RestorePersistedSessionsInput;

const readyReadinessWithReauth = {
  kind: 'ready',
  walletId,
  ed25519: [readyEd25519Lane],
  ecdsa: [readyEcdsaLane],
  reauthRequired: [{ kind: 'ed25519_reauth_required_v1', walletId, rpId, reason: 'missing_auth' }],
};
// @ts-expect-error ready readiness cannot carry reauth-required lanes
readyReadinessWithReauth satisfies UseCaseWalletSessionReadiness;

const invalidProvisioningTransition = {
  from: 'ready',
  to: 'failed',
};
// @ts-expect-error ECDSA provisioning ready state is terminal
invalidProvisioningTransition satisfies EcdsaProvisioningTransition;

const validRegisterTransition = {
  from: 'authenticating',
  to: 'provisioning_ed25519',
} satisfies RegisterWalletTransition;
void validRegisterTransition;

const invalidRegisterTransition = {
  from: 'ready',
  to: 'authenticating',
};
// @ts-expect-error register-wallet ready state is terminal
invalidRegisterTransition satisfies RegisterWalletTransition;

const invalidActivationTransition = {
  from: 'activated',
  to: 'writing_seals',
};
// @ts-expect-error activated signing-session state is terminal
invalidActivationTransition satisfies ActivateSigningSessionTransition;

const invalidRestoreTransition = {
  from: 'ready',
  to: 'cleaning_stale_records',
};
// @ts-expect-error restore ready state is terminal
invalidRestoreTransition satisfies RestorePersistedSessionsTransition;

declare const registerFailure: RegisterWalletTransition;
void registerFailure;
declare const hexValue: typeof hex;
void hexValue;
