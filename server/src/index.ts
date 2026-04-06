// Server package exports - Core NEAR Account Service
export * from './core/types';
export * from './core/config';
export * from './core/defaultConfigsServer';
export { AuthService } from './core/AuthService';
export { SessionService, parseCsvList, buildCorsOrigins } from './core/SessionService';
export type { SessionConfig } from './core/SessionService';
export {
  ThresholdSigningService,
  createThresholdSigningService,
  createThresholdEd25519KeyStore,
  createThresholdEd25519SessionStore,
  createEd25519AuthSessionStore,
  createEcdsaAuthSessionStore,
} from './core/ThresholdService';
export {
  ensureEthSignerWasm,
  computeEip1559TxHash,
  signSecp256k1Recoverable,
  encodeEip1559SignedTxFromSignature65,
  secp256k1PrivateKey32ToPublicKey33,
  secp256k1PublicKey33ToEthereumAddress,
} from './core/ThresholdService/ethSignerWasm';
export type { ServerEip1559UnsignedTx } from './core/ThresholdService/ethSignerWasm';
export {
  ensureThresholdEd25519HssWasm,
  deriveThresholdEd25519HssServerInputs,
  deriveThresholdEd25519HssPublicKey,
  finalizeThresholdEd25519HssServerCeremony,
  openThresholdEd25519HssSeedOutput,
  openThresholdEd25519HssServerOutput,
  prepareThresholdEd25519HssServerCeremony,
  prepareThresholdEd25519HssServerAssistInit,
  finalizeThresholdEd25519HssReport,
} from './core/ThresholdService/ed25519HssWasm';
export type {
  ThresholdEd25519KeyStore,
  ThresholdEd25519KeyRecord,
  ThresholdEd25519SessionStore,
  ThresholdEd25519MpcSessionRecord,
  ThresholdEd25519SigningSessionRecord,
  ThresholdEd25519Commitments,
  Ed25519AuthSessionStore,
  Ed25519AuthSessionRecord,
} from './core/ThresholdService';
export {
  createAccountSignerStore,
  type AccountSignerStore,
  type AccountSignerRecord,
} from './core/AccountSignerStore';
export {
  createSmartAccountRecoverySubjectStore,
  type SmartAccountRecoverySubjectStore,
  type SmartAccountRecoverySubjectRecord,
} from './core/SmartAccountRecoverySubjectStore';
export { buildRegistrationSmartAccountRecords } from './core/smartAccountRegistrationRecords';
export {
  buildLinkDeviceSmartAccountRecords,
  type LinkedSmartAccountRecord,
} from './core/smartAccountLinkDeviceRecords';
export {
  buildCanonicalSmartAccountDeploymentManifest,
  type CanonicalSmartAccountDeploymentManifest,
  type CanonicalSmartAccountDeploymentManifestOwner,
} from './core/smartAccountDeploymentManifest';
export {
  buildCanonicalEvmSmartAccountDeploymentPlan,
  type CanonicalEvmSmartAccountDeploymentPlan,
} from './core/evmSmartAccountDeploymentPlan';
export {
  createRecoverySessionStore,
  type RecoverySessionStore,
  type RecoverySessionRecord,
  type RecoverySessionStatus,
} from './core/RecoverySessionStore';
export {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from './core/recoverySessionRecords';
export {
  createRecoveryExecutionStore,
  type RecoveryExecutionStore,
  type RecoveryExecutionRecord,
  type RecoveryExecutionStatus,
} from './core/RecoveryExecutionStore';
export {
  buildRecoveryExecutionRecord,
  inferNearRecoveryChainIdKey,
} from './core/recoveryExecutionRecords';
export {
  createSponsoredRecoveryDeployedExecutor,
  createSponsoredRecoverySubmittedConfirmer,
  confirmSubmittedSmartAccountRecoveryExecutions,
  executePendingSmartAccountRecoveryExecutions,
  retryFailedSmartAccountRecoveryExecutions,
  type RecoveryAuthorityDeployedExecutionResult,
  type RecoveryAuthorityExecutionResult,
  type RecoveryAuthorityRetryResult,
  type RecoveryAuthorityTargetMode,
  type RecoveryAuthorityTargetResolution,
} from './core/recoveryAuthority';
export { RECOVERY_AUTHORITY_SPONSORED_EVM_ROUTE_ID } from './core/recoveryAuthoritySponsorship';
export {
  buildRecoveryAuthorityAuthorizationDigest,
  deriveRecoveryAuthorityAuthorizationNonce,
  encodeRecoveryAuthorityCalldata,
  getRecoveryAuthorityFunctionSelector,
  getRecoveryAuthorityFunctionSignature,
  signRecoveryAuthorityAuthorization,
  RECOVER_ADD_OWNER_SIGNATURE,
  RECOVERY_AUTHORITY_DOMAIN_NAME,
  RECOVERY_AUTHORITY_DOMAIN_VERSION,
  VERIFY_AND_RECOVER_SIGNATURE,
  type RecoveryAuthorityAuthorization,
  type RecoveryAuthorityContractMethod,
} from './core/recoveryAuthorityAuthorization';
export {
  NEAR_EMAIL_RECOVERY_ACTION,
  SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
  markTrackedRecoverySessionVerified,
  queueTrackedSmartAccountRecoveryExecutions,
  reconcileRecoverySessionExecutionState,
  recordTrackedNearRecoveryExecution,
  resolveTrackedNearRecoveryExecution,
  summarizeSmartAccountRecoveryExecutions,
  transitionTrackedRecoverySession,
  type RecoveryExecutionSummary,
  type TrackedNearRecoveryExecution,
} from './router/recoveryExecutionTracking';
export {
  buildRecoveryAuthoritySponsorshipRuntime,
  parseRecoveryAuthoritySponsorshipScope,
  type RecoveryAuthoritySponsorshipRuntime,
} from './router/recoveryAuthoritySponsorship';
export {
  readCanonicalSmartAccountDeploymentManifest,
  syncCanonicalSmartAccountDeploymentManifest,
} from './router/smartAccountDeploymentManifest';
export { createEvmSmartAccountDeployHandler } from './router/evmSmartAccountDeploy';
export {
  createRecoveryAuthorityIntervalRunner,
  type RecoveryAuthorityIntervalRunner,
} from './router/recoveryAuthorityInterval';
export {
  monitorRecoveryAuthorityExecutions,
  type RecoveryAuthorityMonitoringConfig,
  type RecoveryAuthorityMonitoringSummary,
} from './router/recoveryAuthorityMonitoring';
export * from './email-recovery';
export * from './threshold/session/prfSessionSeal';
export * from './router/ror';
export * from './console/account';
export * from './console/gasSponsorship';
export * from './console/sponsorshipSpendCaps';
export * from './console/billingPrepaidReservations';
export * from './console/sponsoredCalls';
export * from './sponsorship';
