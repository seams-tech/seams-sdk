import express, {
  type NextFunction,
  type Request as ExpressRequest,
  type RequestHandler,
  type Response as ExpressResponse,
  type Router as ExpressRouter,
} from 'express';
import type { RouterApiServiceBag } from './authServicePort';
import { createCloudflareRouter } from './cloudflare/createCloudflareRouter';
import type { RouterApiOptions } from './routerApi';
import {
  attachRouterApiRouteSurface,
  getRouterApiRouteSurface,
} from './routerApiRouteSurface';

export type {
  RouterApiOptions,
  SessionAdapter,
  ThresholdSigningAdapter,
  RouterApiKeyAuthFailureCode,
  RouterApiKeyAuthRequest,
  RouterApiKeyPrincipal,
  RouterApiKeyAuthResult,
  RouterApiKeyAuthAdapter,
  RouterApiPublishableKeyAuthFailureCode,
  RouterApiPublishableKeyAuthRequest,
  RouterApiPublishableKeyAuthResult,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiUsageMeterAction,
  RouterApiUsageMeterEvent,
  RouterApiUsageMeterAdapter,
  RouterApiBootstrapGrantMode,
  RouterApiBootstrapGrantFailureCode,
  RouterApiBootstrapGrantClientContext,
  RouterApiBootstrapGrantIssueRequest,
  RouterApiBootstrapGrant,
  RouterApiBootstrapGrantPaymentRequirement,
  RouterApiBootstrapGrantIssueResult,
  RouterApiBootstrapTokenRecord,
  RouterApiBootstrapGrantBroker,
  RouterApiRuntimePolicyScope,
  RouterApiRuntimeSnapshotEnvelope,
  RouterApiRuntimeSnapshotConsumer,
} from './routerApi';
export {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_PATH,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH,
} from '@shared/utils/routerAbPublicKeyset';
export type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
export type {
  RouterAbNormalSigningAdmissionAdapter,
  RouterAbNormalSigningAdmissionFailure,
  RouterAbNormalSigningAdmissionFailureCode,
  RouterAbNormalSigningAdmissionInput,
  RouterAbNormalSigningAdmissionResult,
} from './routerAbPrivateSigningWorker';
export {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  InMemoryRouterAbNormalSigningAdmissionStore,
  createCloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  createInMemoryRouterAbNormalSigningAdmissionAdapter,
  createInMemoryRouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
} from './routerAbNormalSigningAdmissionStore';
export type {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions,
  InMemoryRouterAbNormalSigningAdmissionStoreOptions,
  RouterAbNormalSigningAbuseDecision,
  RouterAbNormalSigningAbuseProvider,
  RouterAbNormalSigningAdmissionStore,
  RouterAbNormalSigningProjectPolicyDecision,
  RouterAbNormalSigningProjectPolicyProvider,
  RouterAbNormalSigningQuotaDecision,
  RouterAbNormalSigningQuotaStore,
} from './routerAbNormalSigningAdmissionStore';
export type {
  RouterApiCloudflareRouteExtensionInput,
  RouterApiCloudflareRouteExtension,
  RouterApiRouteExtension,
  RouterApiRouteExtensionTransport,
} from './routeExtensions';
export type {
  RouterApiModule,
  RouterApiModuleKind,
  RouterApiModuleOptions,
} from './modules';
export { createRouterApiModule } from './modules';
export type { RouteDefinition } from './routeDefinitions';
export { defineRoute } from './routeDefinitions';
export type {
  ConsoleRouterOptions,
} from './console';
export type {
  ConsoleAuthAdapter,
  ConsoleAuthClaims,
  ConsoleRole,
} from './consoleAuth';
export type {
  ConsoleOrganizationStatus,
  ConsoleProjectStatus,
  ConsoleEnvironmentStatus,
  ConsoleOrganization,
  ConsoleProject,
  ConsoleEnvironment,
  ListConsoleEnvironmentsRequest,
  UpsertConsoleOrganizationRequest,
  CreateConsoleProjectRequest,
  UpdateConsoleProjectRequest,
  CreateConsoleEnvironmentRequest,
  UpdateConsoleEnvironmentRequest,
} from '../console/orgProjectEnv';
export type {
  ConsoleOrgProjectEnvContext,
  ConsoleOrgProjectEnvService,
  D1ConsoleOrgProjectEnvSchemaOptions,
  D1ConsoleOrgProjectEnvServiceOptions,
  InMemoryConsoleOrgProjectEnvServiceOptions,
} from '../console/orgProjectEnv';
export type {
  ConsoleTeamPermissionCategory,
  ConsoleOrgScopedTeamRole,
  ConsoleTeamRole,
  ConsoleTeamRoleScope,
  ConsoleTeamMembershipStatus,
  ConsoleTeamMemberListStatusFilter,
  ConsoleTeamRoleAssignment,
  ConsoleTeamMember,
  ListConsoleTeamMembersRequest,
  InviteConsoleTeamMemberRequest,
  UpdateConsoleTeamMemberRolesRequest,
} from '../console/teamRbac';
export type {
  ConsoleTeamRbacContext,
  ConsoleTeamRbacService,
  D1ConsoleTeamRbacSchemaOptions,
  D1ConsoleTeamRbacServiceOptions,
  InMemoryConsoleTeamRbacServiceOptions,
} from '../console/teamRbac';
export type {
  ConsoleApprovalOperationType,
  ConsoleApprovalStatus,
  ConsoleApprovalDecision,
  ConsoleApprovalDecisionRecord,
  ConsoleApprovalRequestRecord,
  ListConsoleApprovalsRequest,
  CreateConsoleApprovalRequest,
  ApproveConsoleApprovalRequest,
  RejectConsoleApprovalRequest,
} from '../console/approvals';
export type {
  ConsoleApprovalsContext,
  ConsoleApprovalService,
  ConsoleApprovalsD1Runtime,
  ConsoleApprovalsD1Service,
  D1ConsoleApprovalSchemaOptions,
  D1ConsoleApprovalServiceOptions,
  InMemoryConsoleApprovalServiceOptions,
} from '../console/approvals';
export type {
  ConsoleAuditActorType,
  ConsoleAuditCategory,
  ConsoleAuditOutcome,
  ConsoleAuditEvidenceDomain,
  ConsoleAuditEvidenceReferenceKind,
  ConsoleAuditEvent,
  ConsoleAuditEvidenceReference,
  ConsoleAuditEvidenceRecord,
  ListConsoleAuditEventsRequest,
  ListConsoleAuditEvidenceRequest,
  AppendConsoleAuditEventRequest,
  AppendConsoleAuditEvidenceRequest,
} from '../console/audit';
export type {
  ConsoleAuditContext,
  ConsoleAuditService,
  ConsoleAuditD1Runtime,
  ConsoleAuditD1Service,
  D1ConsoleAuditSchemaOptions,
  D1ConsoleAuditServiceOptions,
  InMemoryConsoleAuditServiceOptions,
} from '../console/audit';
export type {
  ConsoleAuditExportDomain,
  ConsoleAuditExportFormat,
  ConsoleAuditExportStatus,
  ConsoleAuditExportFilters,
  ConsoleAuditExportRecord,
  ListConsoleAuditExportsRequest,
  CreateConsoleAuditExportRequest,
} from '../console/auditExports';
export type {
  ConsoleAuditExportsContext,
  ConsoleAuditExportsService,
  InMemoryConsoleAuditExportsServiceOptions,
} from '../console/auditExports';
export type {
  ConsoleEnterpriseIsolationMode,
  ConsoleEnterpriseIsolationStatus,
  ConsoleEnterpriseIsolationTrigger,
  ConsoleEnterpriseIsolationScope,
  ConsoleEnterpriseIsolationSla,
  ConsoleEnterpriseIsolationState,
  GetConsoleEnterpriseIsolationRequest,
  TriggerConsoleEnterpriseIsolationRequest,
} from '../console/enterpriseIsolation';
export type {
  ConsoleEnterpriseIsolationContext,
  ConsoleEnterpriseIsolationService,
  InMemoryConsoleEnterpriseIsolationServiceOptions,
} from '../console/enterpriseIsolation';
export type {
  ConsoleOnboardingStep,
  GetConsoleOnboardingStateRequest,
  ConsoleOnboardingOrgInput,
  ConsoleOnboardingProjectInput,
  CreateConsoleOnboardingOrganizationRequest,
  CreateConsoleOnboardingProjectRequest,
  ConsoleOnboardingState,
  CreateConsoleOnboardingOrganizationResult,
  CreateConsoleOnboardingProjectResult,
} from '../console/onboarding';
export type {
  ConsoleOnboardingContext,
  ConsoleOnboardingService,
  InMemoryConsoleOnboardingServiceOptions,
} from '../console/onboarding';
export type {
  ConsoleAccountBackupEmailStatus,
  ConsoleAccountBackupEmail,
  ConsoleAccountProfile,
  PatchConsoleAccountProfileRequest,
  ConsoleAccountOrganizationAdminCandidate,
  ConsoleAccountOrganization,
  CreateConsoleAccountOrganizationRequest,
  UpdateConsoleAccountOrganizationRequest,
  TransferConsoleAccountOrganizationOwnerRequest,
  TransferConsoleAccountOrganizationOwnerResult,
  DeleteConsoleAccountOrganizationResult,
  SwitchConsoleAccountOrganizationContextResult,
} from '../console/account';
export type {
  ConsoleAccountContext,
  ConsoleAccountService,
  D1ConsoleAccountSchemaOptions,
  D1ConsoleAccountServiceOptions,
  InMemoryConsoleAccountServiceOptions,
} from '../console/account';
export type {
  ConsoleWalletChain,
  ConsoleWalletType,
  ConsoleWalletStatus,
  ConsoleWalletSortBy,
  ConsoleWalletSortOrder,
  ConsoleWallet,
  ListConsoleWalletsRequest,
  SearchConsoleWalletsRequest,
  ConsoleWalletPage,
} from '../console/wallets';
export type {
  ConsoleWalletsContext,
  ConsoleWalletService,
  ConsoleWalletsD1Runtime,
  ConsoleWalletsD1Service,
  D1ConsoleWalletSchemaOptions,
  D1ConsoleWalletServiceOptions,
  InMemoryConsoleWalletServiceOptions,
} from '../console/wallets';
export type {
  ConsolePolicyStatus,
  ConsolePolicyKind,
  ConsolePolicyDecision,
  ConsolePolicyAssignmentScopeType,
  ConsolePolicy,
  ConsolePolicyVersion,
  CreateConsolePolicyRequest,
  UpdateConsolePolicyRequest,
  SimulateConsolePolicyRequest,
  SimulateConsolePolicyResult,
  PublishConsolePolicyResult,
  ConsolePolicyAssignment,
  ListConsolePoliciesRequest,
  ListConsolePolicyAssignmentsRequest,
  UpsertConsolePolicyAssignmentRequest,
  ConsolePolicyWalletScopeRef,
} from '../console/policies';
export type {
  ConsolePoliciesContext,
  ConsolePolicyService,
  D1ConsolePolicySchemaOptions,
  D1ConsolePolicyServiceOptions,
  InMemoryConsolePolicyServiceOptions,
} from '../console/policies';
export type {
  ConsoleApiKeyAuthFailureCode,
  AuthenticateConsoleApiKeyRequest,
  AuthenticateConsoleApiKeySuccess,
  AuthenticateConsoleApiKeyFailure,
  AuthenticateConsoleApiKeyResult,
  ConsoleApiKeyStatus,
  ConsoleApiKey,
  CreateConsoleApiKeyRequest,
  RevokeConsoleApiKeyRequest,
  RotateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
  RotateConsoleApiKeyResult,
} from '../console/apiKeys';
export type {
  ConsoleApiKeysContext,
  ConsoleApiKeyService,
  ConsoleApiKeysD1Runtime,
  ConsoleApiKeysD1Service,
  D1ConsoleApiKeysSchemaOptions,
  D1ConsoleApiKeysServiceOptions,
  InMemoryConsoleApiKeyServiceOptions,
} from '../console/apiKeys';
export type {
  ConsoleBootstrapTokenStatus,
  ConsoleBootstrapTokenRecord,
  CreateConsoleBootstrapTokenRequest,
  CreateConsoleBootstrapTokenResult,
  CountConsoleBootstrapTokensRequest,
  RedeemConsoleBootstrapTokenFailureCode,
  RedeemConsoleBootstrapTokenRequest,
  RedeemConsoleBootstrapTokenResult,
} from '../console/bootstrapTokens';
export type {
  ConsoleBootstrapTokensContext,
  ConsoleBootstrapTokenService,
  ConsoleBootstrapTokensD1Runtime,
  ConsoleBootstrapTokensD1Service,
  D1ConsoleBootstrapTokenSchemaOptions,
  D1ConsoleBootstrapTokenServiceOptions,
  InMemoryConsoleBootstrapTokenServiceOptions,
} from '../console/bootstrapTokens';
export type {
  ConsoleBillingContext,
  ConsoleBillingService,
  InMemoryConsoleBillingServiceOptions,
  ConsoleBillingD1Runtime,
  ConsoleBillingD1Service,
  D1ConsoleBillingServiceOptions,
  D1ConsoleBillingMonthlyFinalizationOptions,
  D1ConsoleBillingMonthlyFinalizationResult,
  StripeCheckoutSessionLookupProviderInput,
  StripeCheckoutSessionLookupProviderOutput,
  StripeCheckoutSessionProviderInput,
  StripeCheckoutSessionProviderOutput,
  StripeWebhookEventRequest,
  StripeWebhookEventResult,
  StripeBillingProviderAdapter,
  BillingProviderAdapters,
} from '../console/billing';
export type {
  ConsoleBillingPrepaidReservationStatus,
  ConsoleBillingPrepaidReservation,
  ConsoleBillingPrepaidReservationSummary,
  ReserveConsoleBillingPrepaidReservationRequest,
  SettleConsoleBillingPrepaidReservationRequest,
  ReleaseConsoleBillingPrepaidReservationRequest,
  ExpireConsoleBillingPrepaidReservationsRequest,
  ConsoleBillingPrepaidReservationReserveOutcome,
  ConsoleBillingPrepaidReservationMutationOutcome,
  ExpireConsoleBillingPrepaidReservationsResult,
  ConsoleBillingPrepaidReservationContext,
  ConsoleBillingPrepaidReservationService,
  InMemoryConsoleBillingPrepaidReservationServiceOptions,
} from '../console/billingPrepaidReservations';
export type {
  ConsoleSponsoredCallApiKeyKind,
  ConsoleSponsoredCallChainFamily,
  ConsoleSponsoredCallIntentKind,
  ConsoleSponsoredCallFeeUnit,
  ConsoleSponsoredCallExecutorKind,
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallRecordPage,
  ConsoleSponsoredCallReconciliationStatus,
  ConsoleSponsoredCallReconciliationEntry,
  ConsoleSponsoredCallReconciliationSummary,
  ConsoleSponsoredCallReconciliationPage,
  ListConsoleSponsoredCallRecordsRequest,
  CreateConsoleSponsoredCallRecordRequest,
  ConsoleSponsoredCallContext,
  ConsoleSponsoredCallService,
  InMemoryConsoleSponsoredCallServiceOptions,
} from '../console/sponsoredCalls';
export type {
  ConsoleWebhookEventCategory,
  ConsoleWebhookEndpointStatus,
  ConsoleWebhookDeliveryStatus,
  ConsoleWebhookEndpoint,
  ConsoleWebhookDelivery,
  ConsoleWebhookDeliveryAttempt,
  ConsoleWebhookDeadLetter,
  ConsoleWebhookPage,
  CreateConsoleWebhookEndpointRequest,
  UpdateConsoleWebhookEndpointRequest,
  ReplayConsoleWebhookDeliveryRequest,
  ListConsoleWebhookDeliveriesRequest,
  ListConsoleWebhookAttemptsRequest,
  ListConsoleWebhookDeadLettersRequest,
  ReplayConsoleWebhookDeliveryResult,
  EmitConsoleWebhookEventRequest,
  EmitConsoleWebhookEventResult,
  ConsoleWebhooksContext,
  WebhookDispatchRequest,
  WebhookDispatchResult,
  WebhookDispatchAdapter,
  InMemoryConsoleWebhookServiceOptions,
  AesGcmConsoleWebhookSecretCipherOptions,
  ConsoleWebhookD1Service,
  ConsoleWebhookSealedSecret,
  ConsoleWebhookSecretCipher,
  ConsoleWebhookSecretOpenInput,
  ConsoleWebhookSecretSealInput,
  ConsoleWebhooksD1Runtime,
  D1ConsoleWebhookSchemaOptions,
  D1ConsoleWebhookRetryDispatchOptions,
  D1ConsoleWebhookRetryDispatchResult,
  D1ConsoleWebhookServiceOptions,
  ConsoleWebhookService,
} from '../console/webhooks';
export type {
  ConsoleSponsorshipSpendCapMode,
  ConsoleSponsorshipSpendCapPeriod,
  ConsoleSponsorshipSpendCapReservationStatus,
  ConsoleSponsorshipSpendCapReservation,
  ConsoleSponsorshipSpendCapWindowUsage,
  ReserveConsoleSponsorshipSpendCapRequest,
  SettleConsoleSponsorshipSpendCapRequest,
  ReleaseConsoleSponsorshipSpendCapRequest,
  GetConsoleSponsorshipSpendCapWindowUsageRequest,
  ConsoleSponsorshipSpendCapReservationOutcome,
} from '../console/sponsorshipSpendCaps';
export type {
  ConsoleSponsorshipSpendCapContext,
  ConsoleSponsorshipSpendCapService,
  ConsoleSponsorshipSpendCapD1Runtime,
  ConsoleSponsorshipSpendCapD1Service,
  D1ConsoleSponsorshipSpendCapSchemaOptions,
  D1ConsoleSponsorshipSpendCapServiceOptions,
  InMemoryConsoleSponsorshipSpendCapServiceOptions,
} from '../console/sponsorshipSpendCaps';
export type {
  ConsoleKeyExportMode,
  ConsoleKeyExportStatus,
  ConsoleKeyExportConstraints,
  ConsoleKeyExportApproval,
  ConsoleKeyExportRequestRecord,
  ListConsoleKeyExportsRequest,
  CreateConsoleKeyExportRequest,
  ApproveConsoleKeyExportRequest,
} from '../console/keyExports';
export type {
  ConsoleKeyExportsContext,
  ConsoleKeyExportService,
  ConsoleKeyExportsD1Runtime,
  ConsoleKeyExportD1Service,
  D1ConsoleKeyExportSchemaOptions,
  D1ConsoleKeyExportServiceOptions,
  InMemoryConsoleKeyExportServiceOptions,
} from '../console/keyExports';
export type {
  ConsoleRuntimeSnapshotPayload,
  ConsoleRuntimeSnapshot,
  ListConsoleRuntimeSnapshotsRequest,
  GetLatestConsoleRuntimeSnapshotRequest,
  PublishConsoleRuntimeSnapshotRequest,
  PublishCurrentConsoleRuntimeSnapshotRequest,
} from '../console/runtimeSnapshots';
export type {
  ConsoleRuntimeSnapshotContext,
  ConsoleRuntimeSnapshotService,
  InMemoryConsoleRuntimeSnapshotServiceOptions,
  ConsoleRuntimeSnapshotOutboxEvent,
} from '../console/runtimeSnapshots';
export type {
  ConsoleObservabilityModuleState,
  ConsoleObservabilityModuleStatus,
  ConsoleObservabilityLevel,
  ConsoleObservabilitySource,
  ConsoleObservabilitySummary,
  ConsoleObservabilityEvent,
  ConsoleObservabilityEventEnvelope,
  ConsoleObservabilityEventsPage,
  ConsoleObservabilityTimeseriesBucket,
  ConsoleObservabilityTimeseries,
  ConsoleServiceHealthState,
  ConsoleObservabilityServiceHealth,
  ConsoleObservabilityServicesView,
  GetConsoleObservabilitySummaryRequest,
  ListConsoleObservabilityEventsRequest,
  GetConsoleObservabilityTimeseriesRequest,
  ListConsoleObservabilityServicesRequest,
  ConsoleObservabilityEventIngestResult,
  ConsoleObservabilityIngestionContext,
  ConsoleObservabilityMetadataRedactionPolicy,
  ConsoleObservabilityWebhookDeadLetterInput,
  ConsoleObservabilityBillingFailureInput,
  ConsoleObservabilityApprovalFailureInput,
} from '../console/observability';
export type {
  ConsoleObservabilityContext,
  ConsoleObservabilityService,
  InMemoryConsoleObservabilityServiceOptions,
  ConsoleObservabilityD1Runtime,
  ConsoleObservabilityD1Service,
  ConsoleObservabilityIngestionD1Service,
  D1ConsoleObservabilitySchemaOptions,
  D1ConsoleObservabilityServiceOptions,
  D1ConsoleObservabilityIngestionServiceOptions,
  ConsoleObservabilityIngestionService,
} from '../console/observability';
export {
  createD1ConsoleOrgProjectEnvService,
  ensureConsoleOrgProjectEnvD1Schema,
  createInMemoryConsoleOrgProjectEnvService,
  isConsoleOrgProjectEnvError,
  ConsoleOrgProjectEnvError,
} from '../console/orgProjectEnv';
export {
  createD1ConsoleTeamRbacService,
  ensureConsoleTeamRbacD1Schema,
  createInMemoryConsoleTeamRbacService,
  parseListConsoleTeamMembersRequest,
  parseInviteConsoleTeamMemberRequest,
  parseUpdateConsoleTeamMemberRolesRequest,
  isConsoleTeamRbacError,
  ConsoleTeamRbacError,
} from '../console/teamRbac';
export {
  CONSOLE_APPROVALS_D1_RUNTIME,
  CONSOLE_APPROVALS_D1_SCHEMA_SQL,
  createD1ConsoleApprovalService,
  ensureConsoleApprovalsD1Schema,
  getConsoleApprovalsD1Runtime,
  createInMemoryConsoleApprovalService,
  parseListConsoleApprovalsRequest,
  parseCreateConsoleApprovalRequest,
  parseApproveConsoleApprovalRequest,
  parseRejectConsoleApprovalRequest,
  isConsoleApprovalsError,
  ConsoleApprovalsError,
} from '../console/approvals';
export {
  CONSOLE_AUDIT_D1_RUNTIME,
  CONSOLE_AUDIT_D1_SCHEMA_SQL,
  createD1ConsoleAuditService,
  ensureConsoleAuditD1Schema,
  getConsoleAuditD1Runtime,
  createInMemoryConsoleAuditService,
  parseListConsoleAuditEventsRequest,
  parseListConsoleAuditEvidenceRequest,
  isConsoleAuditError,
  ConsoleAuditError,
} from '../console/audit';
export {
  createInMemoryConsoleAuditExportsService,
  parseListConsoleAuditExportsRequest,
  parseCreateConsoleAuditExportRequest,
  isConsoleAuditExportsError,
  ConsoleAuditExportsError,
} from '../console/auditExports';
export {
  createInMemoryConsoleEnterpriseIsolationService,
  parseGetConsoleEnterpriseIsolationRequest,
  parseTriggerConsoleEnterpriseIsolationRequest,
  isConsoleEnterpriseIsolationError,
  ConsoleEnterpriseIsolationError,
} from '../console/enterpriseIsolation';
export {
  createInMemoryConsoleOnboardingService,
  parseGetConsoleOnboardingStateRequest,
  parseCreateConsoleOnboardingOrganizationRequest,
  parseCreateConsoleOnboardingProjectRequest,
  isConsoleOnboardingError,
  ConsoleOnboardingError,
} from '../console/onboarding';
export {
  createD1ConsoleAccountService,
  ensureConsoleAccountD1Schema,
  createInMemoryConsoleAccountService,
  parsePatchConsoleAccountProfileRequest,
  parseCreateConsoleAccountOrganizationRequest,
  parseUpdateConsoleAccountOrganizationRequest,
  parseTransferConsoleAccountOrganizationOwnerRequest,
  isConsoleAccountError,
  ConsoleAccountError,
} from '../console/account';
export {
  CONSOLE_WALLETS_D1_RUNTIME,
  CONSOLE_WALLETS_D1_SCHEMA_SQL,
  createD1ConsoleWalletService,
  ensureConsoleWalletsD1Schema,
  getConsoleWalletsD1Runtime,
  createInMemoryConsoleWalletService,
  isConsoleWalletError,
  ConsoleWalletError,
} from '../console/wallets';
export { createInMemoryConsolePolicyService } from '../console/policies/service';
export {
  createD1ConsolePolicyService,
  ensureConsolePolicyD1Schema,
} from '../console/policies';

export {
  isConsolePolicyError,
  ConsolePolicyError,
} from '../console/policies/errors';
export {
  CONSOLE_API_KEYS_D1_RUNTIME,
  CONSOLE_API_KEYS_D1_SCHEMA_SQL,
  createD1ConsoleApiKeyService,
  ensureConsoleApiKeysD1Schema,
  getConsoleApiKeysD1Runtime,
  createInMemoryConsoleApiKeyService,
  isConsoleApiKeyError,
  ConsoleApiKeyError,
} from '../console/apiKeys';
export {
  createInMemoryConsoleBillingService,
  createD1ConsoleBillingService,
  getConsoleBillingD1Runtime,
  createSponsoredExecutionDebitD1InsertStatement,
  runD1ConsoleBillingMonthlyFinalization,
  createDefaultBillingProviderAdapters,
  resolveBillingProviderAdapters,
  isConsoleBillingError,
  ConsoleBillingError,
} from '../console/billing';
export {
  createInMemoryConsoleBillingPrepaidReservationService,
  isConsoleBillingPrepaidReservationError,
  ConsoleBillingPrepaidReservationError,
} from '../console/billingPrepaidReservations';
export {
  createInMemoryConsoleSponsoredCallService,
  listConsoleSponsoredCallReconciliationPage,
  parseListConsoleSponsoredCallRecordsRequest,
  isConsoleSponsoredCallError,
  ConsoleSponsoredCallError,
} from '../console/sponsoredCalls';
export {
  CONSOLE_WEBHOOKS_D1_RUNTIME,
  CONSOLE_WEBHOOKS_D1_SCHEMA_SQL,
  createAesGcmConsoleWebhookSecretCipher,
  createD1ConsoleWebhookService,
  createInMemoryConsoleWebhookService,
  ensureConsoleWebhooksD1Schema,
  getConsoleWebhooksD1Runtime,
  runD1ConsoleWebhookRetryDispatch,
  isConsoleWebhookError,
  ConsoleWebhookError,
} from '../console/webhooks';
export {
  CONSOLE_SPONSORSHIP_SPEND_CAP_D1_RUNTIME,
  CONSOLE_SPONSORSHIP_SPEND_CAP_D1_SCHEMA_SQL,
  createD1ConsoleSponsorshipSpendCapService,
  ensureConsoleSponsorshipSpendCapD1Schema,
  getConsoleSponsorshipSpendCapD1Runtime,
  createInMemoryConsoleSponsorshipSpendCapService,
  isConsoleSponsorshipSpendCapError,
  ConsoleSponsorshipSpendCapError,
} from '../console/sponsorshipSpendCaps';
export {
  CONSOLE_KEY_EXPORTS_D1_RUNTIME,
  CONSOLE_KEY_EXPORTS_D1_SCHEMA_SQL,
  createD1ConsoleKeyExportService,
  ensureConsoleKeyExportsD1Schema,
  getConsoleKeyExportsD1Runtime,
  createInMemoryConsoleKeyExportService,
  parseListConsoleKeyExportsRequest,
  parseCreateConsoleKeyExportRequest,
  parseApproveConsoleKeyExportRequest,
  isConsoleKeyExportError,
  ConsoleKeyExportError,
} from '../console/keyExports';
export {
  createInMemoryConsoleRuntimeSnapshotService,
  parseListConsoleRuntimeSnapshotsRequest,
  parseGetLatestConsoleRuntimeSnapshotRequest,
  parsePublishConsoleRuntimeSnapshotRequest,
  parsePublishCurrentConsoleRuntimeSnapshotRequest,
  isConsoleRuntimeSnapshotError,
  ConsoleRuntimeSnapshotError,
} from '../console/runtimeSnapshots';
export {
  CONSOLE_OBSERVABILITY_D1_RUNTIME,
  CONSOLE_OBSERVABILITY_INGESTION_D1_RUNTIME,
  CONSOLE_OBSERVABILITY_D1_SCHEMA_SQL,
  createD1ConsoleObservabilityService,
  createD1ConsoleObservabilityIngestionService,
  createInMemoryConsoleObservabilityService,
  ensureConsoleObservabilityD1Schema,
  getConsoleObservabilityD1Runtime,
  getConsoleObservabilityIngestionD1Runtime,
  redactConsoleObservabilityMetadata,
  buildWebhookDeadLetterObservabilityEvent,
  buildWebhookRetryExhaustedObservabilityEvent,
  buildWebhookEndpointDegradedObservabilityEvent,
  buildBillingFailureObservabilityEvent,
  buildBillingStripeWebhookFailureObservabilityEvent,
  buildApprovalFailureObservabilityEvent,
  parseGetConsoleObservabilitySummaryRequest,
  parseListConsoleObservabilityEventsRequest,
  parseGetConsoleObservabilityTimeseriesRequest,
  parseListConsoleObservabilityServicesRequest,
  isConsoleObservabilityError,
  ConsoleObservabilityError,
} from '../console/observability';
export { createConsoleRouter } from './express/createConsoleRouter';
export type {
  ConsoleSsoProvisioningOptions,
  AppSessionConsoleAuthAdapterOptions,
} from './consoleAppSessionAuth';
export {
  normalizeConsoleOrgScopedRoleList,
  mergeConsoleOrgScopedRoleLists,
  createAppSessionConsoleAuthAdapter,
} from './consoleAppSessionAuth';
export {
  extractBearerCredential,
  extractRouterApiEnvironmentId,
  resolveSourceIpFromExpressRequest,
  resolveSourceIpFromFetchHeaders,
} from './routerApiKeyAuth';
export {
  createRouterApiKeyAuthAdapter,
  createRouterApiPublishableKeyAuthAdapter,
  createRouterApiBillingUsageMeterAdapter,
} from '../console/router/routerApiKeyAuth';
export type {
  RouterApiBootstrapGrantRateLimitPolicy,
  RouterApiBootstrapGrantQuotaPolicy,
  RouterApiBootstrapGrantBrokerOptions,
} from '../console/router/bootstrapGrantBroker';
export {
  createRouterApiBootstrapGrantBroker,
} from '../console/router/bootstrapGrantBroker';
export {
  createRouterApiBootstrapTokenVerifier,
} from '../console/router/bootstrapTokenVerifier';
export {
  RouterApiBootstrapGrantError,
  parseRouterApiBootstrapGrantIssueBody,
} from './bootstrapGrantBroker';
export {
  CONSOLE_BOOTSTRAP_TOKENS_D1_RUNTIME,
  CONSOLE_BOOTSTRAP_TOKENS_D1_SCHEMA_SQL,
  createD1ConsoleBootstrapTokenService,
  ensureConsoleBootstrapTokensD1Schema,
  getConsoleBootstrapTokensD1Runtime,
  createInMemoryConsoleBootstrapTokenService,
} from '../console/bootstrapTokens';
export type {
  RouterApiRuntimeSnapshotPublishedUpdate,
  InMemoryRouterApiRuntimeSnapshotConsumer,
} from './runtimeSnapshotConsumer';
export {
  validateRuntimeSnapshotExpectation,
  createInMemoryRouterApiRuntimeSnapshotConsumer,
} from './runtimeSnapshotConsumer';

function appendExpressRequestHeaders(headers: Headers, req: ExpressRequest): void {
  for (const [name, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
      continue;
    }
    if (typeof value === 'string') headers.set(name, value);
  }
}

function resolveExpressRequestUrl(req: ExpressRequest): string {
  const host = req.get('host') || 'localhost';
  const protocol = req.protocol || 'http';
  return `${protocol}://${host}${req.originalUrl || req.url}`;
}

function encodeExpressRequestBody(req: ExpressRequest): BodyInit | undefined {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD') return undefined;
  if (req.body === undefined || req.body === null) return undefined;
  if (typeof req.body === 'string' || req.body instanceof Uint8Array) return req.body;
  return JSON.stringify(req.body);
}

function buildFetchRequestFromExpress(req: ExpressRequest): Request {
  const headers = new Headers();
  appendExpressRequestHeaders(headers, req);
  const body = encodeExpressRequestBody(req);
  if (body && !headers.has('content-type')) {
    headers.set('content-type', 'application/json; charset=utf-8');
  }
  return new Request(resolveExpressRequestUrl(req), {
    method: req.method,
    headers,
    body,
  });
}

async function isFetchRouterNotFound(response: Response): Promise<boolean> {
  if (response.status !== 404) return false;
  const text = await response.clone().text();
  return text === 'Not Found';
}

async function sendFetchResponseToExpress(
  fetchResponse: Response,
  res: ExpressResponse,
): Promise<void> {
  fetchResponse.headers.forEach((value, name) => {
    res.setHeader(name, value);
  });
  res.status(fetchResponse.status);
  const body = Buffer.from(await fetchResponse.arrayBuffer());
  if (body.length === 0) {
    res.end();
    return;
  }
  res.send(body);
}

function createFetchBackedExpressMiddleware(
  fetchHandler: ReturnType<typeof createCloudflareRouter>,
): RequestHandler {
  return async function fetchBackedExpressMiddleware(
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction,
  ): Promise<void> {
    try {
      const fetchRequest = buildFetchRequestFromExpress(req);
      const fetchResponse = await fetchHandler(fetchRequest);
      if (await isFetchRouterNotFound(fetchResponse)) {
        next();
        return;
      }
      await sendFetchResponseToExpress(fetchResponse, res);
    } catch (error) {
      next(error);
    }
  };
}

export function createRouterApiRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions = {},
): ExpressRouter {
  const fetchHandler = createCloudflareRouter(service, opts);
  const router = express.Router();
  router.use(createFetchBackedExpressMiddleware(fetchHandler));
  const surface = getRouterApiRouteSurface(fetchHandler);
  if (!surface) return router;
  return attachRouterApiRouteSurface(router, surface);
}
