// Server package exports - Core NEAR Account Service
export * from './core/types';
export * from './core/config';
export * from './core/defaultConfigsServer';
export {
  formatSigningSessionSealKeyVersionForWire,
  formatSigningSessionSealShamirPrimeB64uForWire,
  parseSigningSessionSealKeyVersion,
  parseSigningSessionSealShamirPrimeB64u,
  type SigningSessionSealKeyVersion,
  type SigningSessionSealShamirPrimeB64u,
} from './core/keyMaterialBrands';
export { AuthService } from './core/AuthService';
export { SessionService, parseCsvList, buildCorsOrigins } from './core/SessionService';
export type { SessionConfig } from './core/SessionService';
export {
  ThresholdSigningService,
  createThresholdSigningService,
  createThresholdEd25519KeyStore,
  createThresholdEd25519SessionStore,
  createEd25519WalletSessionStore,
  createEcdsaWalletSessionStore,
  createWalletSigningBudgetSessionStore,
  CloudflareDurableObjectSigningRootSecretStore,
  D1SigningRootSecretStore,
  SIGNING_ROOT_SECRET_SHARE_D1_SCHEMA_SQL,
  createConfiguredSigningRootShareResolver,
  createHostedSigningRootShareResolver,
  createSelfHostedSigningRootShareResolver,
  ensureSigningRootSecretShareD1Schema,
  deriveEcdsaHssYRelayerFromSigningRootShareResolver,
  deriveEd25519HssServerInputsFromSigningRootShareResolver,
  computeSigningRootMigrationBundleChecksumB64u,
  createSigningRootMigrationExportArtifact,
  createSigningRootMigrationWalletInventory,
} from './core/ThresholdService';
export type {
  CreateHostedSigningRootShareResolverInput,
  CreateSelfHostedSigningRootShareResolverInput,
  DeriveEcdsaHssYRelayerFromSigningRootShareResolverInput,
  DeriveEd25519HssServerInputsFromSigningRootShareResolverInput,
  D1SigningRootSecretStoreOptions,
  D1SigningRootSecretStoreSchemaOptions,
  FixedSigningRootScope,
  SealedSigningRootShare,
  SigningRootShareDecryptAdapter,
  SigningRootShareSource,
  SigningRootSecretShareId,
  SigningRootSecretShareKekResolver,
  SigningRootSecretShareKekResolutionInput,
  SigningRootSecretStore,
  SealedSigningRootSecretShare,
  SigningRootSecretShareSource,
  SigningRootSecretShareWireV1,
  SigningRootShareInput,
  SigningRootShareResolverInput,
  SigningRootShareResolver,
  SigningRootShareSet,
  ThresholdPrfPolicy,
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
  deriveThresholdEd25519HssPublicKey,
  finalizeThresholdEd25519HssServerCeremony,
  openThresholdEd25519HssSeedOutput,
  openThresholdEd25519HssServerOutput,
  prepareThresholdEd25519HssRoleSeparatedServerInputDelivery,
  prepareThresholdEd25519HssServerCeremony,
  finalizeThresholdEd25519HssReport,
} from './core/ThresholdService/ed25519HssWasm';
export type {
  ThresholdEd25519KeyStore,
  ThresholdEd25519KeyRecord,
  ThresholdEd25519SessionStore,
  ThresholdEd25519MpcSessionRecord,
  ThresholdEd25519SigningSessionRecord,
  ThresholdEd25519Commitments,
  Ed25519WalletSessionStore,
  Ed25519WalletSessionRecord,
} from './core/ThresholdService';
export {
  D1RecoverySessionStore,
  ensureRecoverySessionStoreD1Schema,
  createRecoverySessionStore,
  RECOVERY_SESSION_STORE_D1_SCHEMA_SQL,
  type D1RecoverySessionStoreOptions,
  type D1RecoverySessionStoreSchemaOptions,
  type RecoverySessionStore,
  type RecoverySessionRecord,
  type RecoverySessionStatus,
} from './core/RecoverySessionStore';
export {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from './core/recoverySessionRecords';
export {
  D1EmailRecoveryPreparationStore,
  EMAIL_RECOVERY_PREPARATION_STORE_D1_SCHEMA_SQL,
  createEmailRecoveryPreparationStore,
  ensureEmailRecoveryPreparationStoreD1Schema,
  type D1EmailRecoveryPreparationStoreOptions,
  type D1EmailRecoveryPreparationStoreSchemaOptions,
  type EmailRecoveryPreparationRecord,
  type EmailRecoveryPreparationStore,
} from './core/EmailRecoveryPreparationStore';
export {
  D1RecoveryExecutionStore,
  ensureRecoveryExecutionStoreD1Schema,
  createRecoveryExecutionStore,
  RECOVERY_EXECUTION_STORE_D1_SCHEMA_SQL,
  type D1RecoveryExecutionStoreOptions,
  type D1RecoveryExecutionStoreSchemaOptions,
  type RecoveryExecutionStore,
  type RecoveryExecutionRecord,
  type RecoveryExecutionStatus,
} from './core/RecoveryExecutionStore';
export {
  buildRecoveryExecutionRecord,
  inferNearRecoveryChainIdKey,
} from './core/recoveryExecutionRecords';
export {
  D1WalletAuthMethodStore,
  createWalletAuthMethodStore,
  ensureWalletAuthMethodStoreD1Schema,
  normalizeWalletAuthMethod,
  resolveWalletAuthMethodStoreNamespace,
  WALLET_AUTH_METHOD_STORE_D1_SCHEMA_SQL,
  type D1WalletAuthMethodStoreOptions,
  type D1WalletAuthMethodStoreSchemaOptions,
  type WalletAuthMethodRecord,
  type WalletAuthMethodStore,
} from './core/WalletAuthMethodStore';
export {
  D1WalletStore,
  WALLET_STORE_D1_SCHEMA_SQL,
  buildWalletEcdsaSignerRecord,
  buildWalletEd25519SignerId,
  createWalletStore,
  ensureWalletStoreD1Schema,
  resolveWalletStoreNamespace,
  type D1WalletStoreOptions,
  type D1WalletStoreSchemaOptions,
  type WalletEcdsaSignerRecord,
  type WalletEd25519SignerRecord,
  type WalletRecord,
  type WalletSignerRecord,
  type WalletStore,
} from './core/WalletStore';
export {
  D1WebAuthnAuthenticatorStore,
  WEBAUTHN_AUTHENTICATOR_STORE_D1_SCHEMA_SQL,
  createWebAuthnAuthenticatorStore,
  ensureWebAuthnAuthenticatorStoreD1Schema,
  resolveWebAuthnAuthenticatorStoreNamespace,
  type D1WebAuthnAuthenticatorStoreOptions,
  type D1WebAuthnAuthenticatorStoreSchemaOptions,
  type WebAuthnAuthenticatorRecord,
  type WebAuthnAuthenticatorStore,
} from './core/WebAuthnAuthenticatorStore';
export {
  D1WebAuthnCredentialBindingStore,
  WEBAUTHN_CREDENTIAL_BINDING_STORE_D1_SCHEMA_SQL,
  createWebAuthnCredentialBindingStore,
  ensureWebAuthnCredentialBindingStoreD1Schema,
  resolveWebAuthnCredentialBindingStoreNamespace,
  type D1WebAuthnCredentialBindingStoreOptions,
  type D1WebAuthnCredentialBindingStoreSchemaOptions,
  type WebAuthnCredentialBindingRecord,
  type WebAuthnCredentialBindingStore,
} from './core/WebAuthnCredentialBindingStore';
export {
  D1WebAuthnLoginChallengeStore,
  WEBAUTHN_LOGIN_CHALLENGE_STORE_D1_SCHEMA_SQL,
  createWebAuthnLoginChallengeStore,
  ensureWebAuthnLoginChallengeStoreD1Schema,
  type D1WebAuthnLoginChallengeStoreOptions,
  type D1WebAuthnLoginChallengeStoreSchemaOptions,
  type WebAuthnLoginChallengeRecord,
  type WebAuthnLoginChallengeStore,
} from './core/WebAuthnLoginChallengeStore';
export {
  D1WebAuthnSyncChallengeStore,
  WEBAUTHN_SYNC_CHALLENGE_STORE_D1_SCHEMA_SQL,
  createWebAuthnSyncChallengeStore,
  ensureWebAuthnSyncChallengeStoreD1Schema,
  type D1WebAuthnSyncChallengeStoreOptions,
  type D1WebAuthnSyncChallengeStoreSchemaOptions,
  type WebAuthnSyncChallengeRecord,
  type WebAuthnSyncChallengeStore,
} from './core/WebAuthnSyncChallengeStore';
export {
  D1IdentityStore,
  IDENTITY_STORE_D1_SCHEMA_SQL,
  createIdentityStore,
  ensureIdentityStoreD1Schema,
  resolveIdentityStoreNamespace,
  type AppSessionVersionRecord,
  type D1IdentityStoreOptions,
  type D1IdentityStoreSchemaOptions,
  type IdentityStore,
  type IdentitySubjectRecord,
  type IdentityUserRecord,
  type LinkIdentityResult,
  type UnlinkIdentityResult,
} from './core/IdentityStore';
export {
  D1NearPublicKeyStore,
  NEAR_PUBLIC_KEY_STORE_D1_SCHEMA_SQL,
  createNearPublicKeyStore,
  ensureNearPublicKeyStoreD1Schema,
  type D1NearPublicKeyStoreOptions,
  type D1NearPublicKeyStoreSchemaOptions,
  type NearPublicKeyKind,
  type NearPublicKeyRecord,
  type NearPublicKeyStore,
} from './core/NearPublicKeyStore';
export {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  InMemoryRouterAbNormalSigningAdmissionStore,
  createCloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  createInMemoryRouterAbNormalSigningAdmissionAdapter,
  createInMemoryRouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
  type CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions,
  type InMemoryRouterAbNormalSigningAdmissionStoreOptions,
  type RouterAbNormalSigningAbuseDecision,
  type RouterAbNormalSigningAbuseProvider,
  type RouterAbNormalSigningAdmissionStore,
  type RouterAbNormalSigningProjectPolicyDecision,
  type RouterAbNormalSigningProjectPolicyProvider,
  type RouterAbNormalSigningQuotaDecision,
  type RouterAbNormalSigningQuotaStore,
} from './router/routerAbNormalSigningAdmissionStore';
export * from './email-recovery';
export * from './threshold/session/signingSessionSeal';
export type {
  RouterApiModule,
  RouterApiModuleKind,
  RouterApiModuleOptions,
} from './router/modules';
export { createRouterApiModule } from './router/modules';
export type {
  RouterApiCloudflareRouteExtension,
  RouterApiCloudflareRouteExtensionInput,
  RouterApiExpressRouteExtension,
  RouterApiExpressRouteExtensionInput,
  RouterApiRouteExtension,
  RouterApiRouteExtensionTransport,
} from './router/routeExtensions';
export * from './router/ror';
export * from './storage/tenantRoute';
export * from './console/account';
export * from './console/gasSponsorship';
export * from './console/sponsorshipSpendCaps';
export * from './console/billingPrepaidReservations';
export * from './console/sponsoredCalls';
export * from './sponsorship';
