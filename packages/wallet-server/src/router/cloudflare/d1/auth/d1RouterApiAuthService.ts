import type { FinalizeWalletAddAuthMethodCommand } from '../../../framework/authServicePort';
import type { WalletAddAuthMethodFinalizeResponse } from '../../../../core/registrationContracts';
import {
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  RegistrationEstablishedEcdsaSession,
  RegistrationEstablishedEd25519Session,
  RegistrationEstablishedSession,
} from '@shared/utils/registrationEstablishedSession';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseWalletId,
} from '@shared/utils/domainIds';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type { WalletAuthMethodRecord } from '@shared/utils/registrationIntent';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { parseThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import type { WalletRegistrationActivateResponseV2 } from '../../../../core/threeRouteRegistrationContracts';
import { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import { D1WalletStore } from '../../../../core/d1WalletStore';
import {
  resolveActiveOwnerWalletExecutionLane,
  resolveWalletAuthMethodIdForAuthority,
  type WalletExecutionLaneProjectionResult,
  type WalletExecutionLaneProjectionSource,
} from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import { D1IdentityStore } from '../../../../core/d1IdentityStore';
import type { IdentityStore, LinkIdentityResult } from '../../../../core/IdentityStore';
import type { D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import { normalizeLogger } from '../../../../core/logger';
import { toPublicKeyStringFromSecretKey } from '../../../../core/nearKeys';
import { signGasRelayerNearTransactionWithDeps } from '../../../../core/authService/nearTransactions';
import {
  ensureSignerWasmRuntime,
  type SignerWasmRuntimeState,
} from '../../../../core/authService/wasm';
import { MinimalNearClient } from '../../../../core/rpcClients/near/NearClient';
import {
  executeSignedDelegateWithRelayer,
  type ExecuteSignedDelegateRequest,
  type ExecuteSignedDelegateResult,
} from '../../../../delegateAction';
import type { ActionArgsWasm } from '@shared/near/actions';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type {
  AccountCreationResult,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
} from '../../../../core/types';
import type {
  RouterApiServiceBag,
  RouterApiWalletRegistrationService,
} from '../../../framework/authServicePort';
import { AuthorizationService } from '../../../../authorization/service';
import { capabilityPolicyPort } from '../../../../authorization/capabilityPolicy';
import { CloudflareD1AuthorizationStore } from '../authorization/d1AuthorizationStore';
import { parseTenantId } from '@shared/authorization/capabilityKinds';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../registration/d1RegistrationCeremonyStore';
import type { LinkedOwnerEnrollmentCeremonyReaderV1 } from '../../../../core/deviceLinking/linkedOwnerEnrollmentProvenance';
import { isRecordValue, sha256BytesPortable } from './d1RouterApiAuthBoundary';
import { CloudflareD1NearPublicKeyStore } from '../near/d1NearPublicKeyStore';
import { CloudflareD1WebAuthnStore } from '../webauthn/d1WebAuthnStore';
import { CloudflareD1EmailOtpChallengeStore } from '../emailOtp/d1EmailOtpChallengeStore';
import { CloudflareD1EmailOtpDeliveryRuntime } from '../emailOtp/d1EmailOtpDeliveryRuntime';
import { CloudflareD1EmailOtpEnrollmentStore } from '../emailOtp/d1EmailOtpEnrollmentStore';
import { CloudflareD1EmailOtpGrantStore } from '../emailOtp/d1EmailOtpGrantStore';
import { CloudflareD1EmailOtpRateLimitStore } from '../emailOtp/d1EmailOtpRateLimitStore';
import { CloudflareD1EmailOtpServerSealRuntime } from '../emailOtp/d1EmailOtpServerSealRuntime';
import { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from '../emailOtp/d1EmailOtpRegistrationEnrollmentFinalizer';
import { CloudflareD1EmailOtpChallengeVerifier } from '../emailOtp/d1EmailOtpChallengeVerifier';
import { CloudflareD1EmailOtpChallengeIssuer } from '../emailOtp/d1EmailOtpChallengeIssuer';
import { CloudflareD1EmailOtpChallengeService } from '../emailOtp/d1EmailOtpChallengeService';
import { CloudflareD1EmailOtpRecoveryService } from '../emailOtp/d1EmailOtpRecoveryService';
import { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from '../emailOtp/d1GoogleEmailOtpRegistrationAttemptStore';
import { CloudflareD1GoogleEmailOtpSessionResolver } from '../emailOtp/d1GoogleEmailOtpSessionResolver';
import { CloudflareD1IdentityService } from '../identity/d1IdentityService';
import { CloudflareD1OidcVerificationService } from '../oidc/d1OidcVerificationService';
import {
  CloudflareD1WebAuthnAuthService,
  type D1WebAuthnWalletManifestSource,
} from '../webauthn/d1WebAuthnAuthService';
import { CloudflareD1WalletAuthMethodService } from '../wallet/d1WalletAuthMethodService';
import {
  CloudflareD1WalletRegistrationService,
  type D1WalletRegistrationOperationPreparedV1,
  type D1WalletRegistrationActivateSideEffectRecord,
  type D1WalletRegistrationActivateSideEffectStore,
  type D1WalletRegistrationNearProvisioningSideEffectRecord,
  type D1WalletRegistrationNearProvisioningSideEffectStore,
  type SponsoredNamedNearAccountCreationResult,
} from '../registration/d1WalletRegistrationService';
import {
  parseD1EcdsaDerivationServerBootstrapResponse,
  parseD1WalletRegistrationFinalizeTerminalResponse,
} from '../registration/d1RegistrationCeremonyRecords';
import { CloudflareD1WalletRegistrationCommitStore } from '../registration/d1WalletRegistrationCommitStore';
import { CloudflareD1WalletCustodyCommitStore } from '../passkeyCustody/d1WalletCustodyCommitStore';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import { createD1PasskeyCustodyRouteService } from '../passkeyCustody/d1PasskeyCustodyRouteService';
import {
  CloudflareD1WalletAddSignerService,
  parseD1WalletAddSignerFinalizeSideEffectRecord,
  parseD1WalletAddSignerStartSideEffectRecord,
  type D1WalletAddSignerFinalizeSideEffectRecord,
  type D1WalletAddSignerFinalizeSideEffectStore,
  type D1WalletAddSignerStartSideEffectRecord,
  type D1WalletAddSignerStartSideEffectStore,
} from '../wallet/d1WalletAddSignerService';
import { CloudflareD1RegistrationIntentService } from '../registration/d1RegistrationIntentService';
import {
  broadcastPreparedSponsoredNearAccountCreation,
  fundImplicitNearAccountWithRelayer,
  preparedSponsoredNearAccountCreationArtifactFingerprint,
  prepareSponsoredNearAccountCreationWithRelayer,
  type PreparedSponsoredNearAccountCreationV1,
} from '../../../../core/nearRelayerAccountProvisioning';
import {
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  type RouterAbEd25519YaoRegistrationSideEffectStoreV1,
} from '../../../domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationSideEffectBoundary';
import { createCloudflareD1VersionedJsonRecordStore } from '../versionedJson/d1VersionedJsonRecordStore';
import type { VersionedJsonObject } from '../../../framework/versionedJsonRecordStore';
import {
  normalizeD1RouterApiAuthOptions,
  type CloudflareD1RouterApiAuthServiceOptions,
  type NormalizedCloudflareD1RouterApiAuthServiceOptions,
} from './d1RouterApiAuthConfig';
import type { RouterAbEd25519YaoProductRegistrationRuntimeV1 } from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import { createD1LinkedDeviceRouteServiceV1 } from '../deviceLinking/d1LinkedDeviceRouteService';
import { createD1LinkedDeviceManagementRouteServiceV1 } from '../deviceLinking/d1LinkedDeviceManagementRouteService';
import {
  D1LinkedDeviceManagementStoreV1,
  D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1,
} from '../deviceLinking/d1LinkedDeviceManagementStore';
import {
  AuthorizationServiceLinkedDeviceWalletSessionRevocationV1,
  D1LinkedDeviceOwnerCredentialRevocationV1,
  D1LinkedDeviceRevocationPreparationV1,
  D1LinkedDeviceWalletSessionAuthorizationMetadataSourceV1,
} from '../deviceLinking/d1LinkedDeviceManagementComposition';
import { createD1LinkedDeviceGatewayCompletionServiceV1 } from '../deviceLinking/d1LinkedDeviceGatewayCompletionService';
import {
  D1LinkedDeviceTargetCredentialProviderV1,
  LinkedDeviceWebAuthnRegistrationVerifierV1,
} from '../deviceLinking/d1LinkedDeviceTargetCredentialProvider';
import { D1LinkedDeviceOwnerPlanningSnapshotStoreV1 } from '../deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotStore';
import { D1LinkedDeviceOwnerPlanningSnapshotWriterV1 } from '../deviceLinking/d1LinkedDeviceOwnerPlanningSnapshotWriter';
import { D1LinkedDeviceOwnerPlanningDeploymentV1 } from '../deviceLinking/d1LinkedDeviceOwnerPlanningDeployment';
import { createD1LinkedDeviceOwnerAuthorizationProviderV1 } from '../deviceLinking/d1LinkedDeviceOwnerAuthorizationProvider';
import { D1LinkedDeviceProvisioningProviderV1 } from '../deviceLinking/d1LinkedDeviceProvisioningProvider';
import { D1LinkedDeviceSourceHandoffProviderV1 } from '../deviceLinking/d1LinkedDeviceSourceHandoffProvider';
import { createLinkedDeviceR102ProvisioningExecutionV1 } from '../deviceLinking/linkedDeviceR102ProvisioningExecution';
import {
  createD1LinkedDeviceCredentialResolverV1,
  createD1LinkedDeviceLocalPresenceVerifierV1,
} from '../deviceLinking/d1LinkedDeviceTargetAuthenticatorStore';
import { D1LinkedDeviceExecutionAdmissionResolverV1 } from '../deviceLinking/d1LinkedDeviceExecutionAdmissionResolver';
import {
  D1LinkedDeviceEmailOtpGrantStoreV1,
  createLinkedDeviceEmailOtpRegistrationPortV1,
} from '../deviceLinking/d1LinkedDeviceEmailOtpGrantStore';
import {
  D1LinkedDeviceEmailOtpTargetFactorV1,
  linkedDeviceEmailOtpBaseFactorReaderV1,
} from '../deviceLinking/d1LinkedDeviceEmailOtpTargetFactor';
import { D1LinkedDeviceLocalStateInvalidationV1 } from '../deviceLinking/d1LinkedDeviceLocalStateInvalidation';
import { D1LinkedDeviceOperatorRecoveryProviderV1 } from '../deviceLinking/d1LinkedDeviceOperatorRecoveryProvider';
import { D1LinkedDeviceOwnerAuthBindingStoreV1 } from '../deviceLinking/d1LinkedDeviceOwnerAuthBindingStore';
import { CloudflareD1LaneEnrollmentGateway } from '../signingLanes/d1LaneEnrollmentGateway';
import { createCloudflareD1LaneAggregateRevocationApplicationService } from '../signingLanes/d1LaneAggregateRevocationApplicationService';
import { createCloudflareD1LaneLifecycleApplicationService } from '../signingLanes/d1LaneLifecycleApplicationService';
import { CloudflareD1LaneLifecycleStore } from '../signingLanes/d1LaneLifecycleStore';
import { createD1LinkedDeviceLaneRuntimeV1 } from '../signingLanes/d1LinkedDeviceLaneRuntime';
import { createDeviceLinkingOwnerRequestAuthenticatorV1 } from '../../../transport/fetch/routes/deviceLinkingOwnerAuthorization';

export type {
  CloudflareD1EmailOtpDeliveryProvider,
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
  CloudflareD1EmailOtpServerSealConfig,
  CloudflareD1LinkedDeviceCompositionOptionsV1,
  CloudflareD1LinkedDeviceExecutionOptionsV1,
  CloudflareD1LinkedDeviceLaneRuntimeOptionsV1,
  CloudflareD1LinkedDeviceSessionOptionsV1,
  CloudflareD1LinkedDeviceManagementOptionsV1,
  CloudflareD1LinkedDeviceGatewayOptionsV1,
  CloudflareD1RouterApiAuthServiceOptions,
} from './d1RouterApiAuthConfig';

export type CloudflareD1RouterApiAuthService = Omit<RouterApiServiceBag, 'thresholdRuntime'> & {
  readonly thresholdRuntime: RouterApiServiceBag['thresholdRuntime'];
  readonly executeSignedDelegate: (
    input: ExecuteSignedDelegateRequest,
  ) => Promise<ExecuteSignedDelegateResult>;
};

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;
const DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT = 'cloudflare-d1-relayer.local';
const DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY = 'd1-relayer-public-key';

type D1IdentityLinkInput = {
  readonly userId: string;
  readonly subject: string;
  readonly allowMoveIfSoleIdentity?: boolean;
};

type SponsoredNamedNearAccountInput = {
  readonly accountId: string;
  readonly publicKey: string;
  /**
   * Registration-scoped key for the durable claim. Two attempts at the same
   * registration share a key so the second replays the first's transaction.
   */
  readonly idempotencyKey: string;
};

type CloudflareD1RouterApiLazyStoreState = {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  walletStore: D1WalletStore | null;
  walletAuthMethodStore: D1WalletAuthMethodStore | null;
  registrationCeremonyIntentStore: CloudflareD1RegistrationCeremonyIntentStore | null;
};

type CloudflareD1RouterApiAuthAssembly = {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  readonly emailOtpServerSeal: CloudflareD1EmailOtpServerSealRuntime;
  readonly emailOtpChallengeService: CloudflareD1EmailOtpChallengeService;
  readonly emailOtpRecoveryService: CloudflareD1EmailOtpRecoveryService;
  readonly identityService: CloudflareD1IdentityService;
  readonly oidcVerification: CloudflareD1OidcVerificationService;
  readonly authorizationService: AuthorizationService;
  readonly googleEmailOtpSessions: CloudflareD1GoogleEmailOtpSessionResolver;
  readonly nearPublicKeys: CloudflareD1NearPublicKeyStore;
  readonly webAuthnAuthService: CloudflareD1WebAuthnAuthService;
  readonly walletAuthMethods: CloudflareD1WalletAuthMethodService;
  readonly walletRegistrations: CloudflareD1WalletRegistrationService;
  readonly walletStore: D1WalletStore;
  readonly walletAuthMethodStore: D1WalletAuthMethodStore;
  readonly walletAddSigners: CloudflareD1WalletAddSignerService;
  readonly registrationIntents: CloudflareD1RegistrationIntentService;
  readonly signedDelegateExecutor: CloudflareD1SignedDelegateExecutor;
  readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
  /* The same store registration commits through: recovery spends update the
     record registration wrote, so a second store here would let a spend land
     against a set nothing else can see. */
  readonly walletCustodyCommitStore: CloudflareD1WalletCustodyCommitStore;
  /* Exposed because custody retrieval verifies the assertion against the same
     authenticators WebAuthn registration wrote. A second store here would let
     a credential be active for one and unknown to the other. */
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly deviceLinking?: RouterApiServiceBag['deviceLinking'];
  readonly deviceManagement?: RouterApiServiceBag['deviceManagement'];
  readonly linkedDeviceExecution?: RouterApiServiceBag['linkedDeviceExecution'];
  readonly linkedDeviceLocalPresence?: RouterApiServiceBag['linkedDeviceLocalPresence'];
  readonly deviceLinkingGateway?: RouterApiServiceBag['deviceLinkingGateway'];
  readonly deviceLinkingOwnerAuthorization?: RouterApiServiceBag['deviceLinkingOwnerAuthorization'];
  readonly deviceLinkingLaneGateway?: RouterApiServiceBag['deviceLinkingLaneGateway'];
};

type D1WalletRegistrationRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  | 'emailOtpRecoveryService'
  | 'registrationIntents'
  | 'walletAuthMethodStore'
  | 'walletRegistrations'
  | 'walletStore'
>;

type D1WalletAuthMethodRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'registrationIntents' | 'walletAuthMethods' | 'walletAddSigners'
>;

type D1WalletUnlockRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'emailOtpRecoveryService' | 'webAuthnAuthService'
>;

type D1EmailOtpRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  | 'emailOtpServerSeal'
  | 'emailOtpChallengeService'
  | 'emailOtpRecoveryService'
  | 'googleEmailOtpSessions'
  | 'oidcVerification'
>;

type D1WebAuthnRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'webAuthnAuthService'
>;

type D1IdentityRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'googleEmailOtpSessions' | 'identityService' | 'oidcVerification' | 'options'
>;

type D1AuthorizationSessionRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'authorizationService' | 'options'
>;

type D1ThresholdRuntimeRouteServiceAssembly = Pick<CloudflareD1RouterApiAuthAssembly, 'options'>;

type D1NearFundingRouteServiceAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  'nearPublicKeys' | 'options'
>;

type D1RouterAccountRouteServiceAssembly = Pick<CloudflareD1RouterApiAuthAssembly, 'options'>;

type D1LinkedDeviceCompositionAssembly = Pick<
  CloudflareD1RouterApiAuthAssembly,
  | 'deviceLinking'
  | 'deviceManagement'
  | 'linkedDeviceExecution'
  | 'linkedDeviceLocalPresence'
  | 'deviceLinkingGateway'
  | 'deviceLinkingOwnerAuthorization'
  | 'deviceLinkingLaneGateway'
>;

function createD1LinkedDeviceComposition(input: {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  readonly authorizationSessions: RouterApiServiceBag['authorizationSessions'];
  readonly walletStore: D1WalletStore;
  readonly walletRegistration: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane' | 'listWalletEcdsaCustodyContinuity'
  >;
  readonly authorization: Pick<
    CloudflareD1AuthorizationStore,
    'readClaimedLinkedDeviceWalletSessionAuthorization'
  >;
  /**
   * The registration ceremony store, read back so an approval's owner
   * enrollment is proved to be the server's own ceremony before its digest
   * seals it.
   */
  readonly ownerEnrollmentCeremonies: LinkedOwnerEnrollmentCeremonyReaderV1;
  /**
   * Refactor 103 Phase 6: the R100 Email OTP pieces the linked-device Email
   * OTP target factor composes. Left absent, `email_otp` linking fails closed
   * at approval and the challenge routes answer 501.
   */
  readonly emailOtpLinkedDevice?: {
    readonly issuer: Pick<CloudflareD1EmailOtpChallengeIssuer, 'create'>;
    readonly verifier: Pick<CloudflareD1EmailOtpChallengeVerifier, 'verifyExisting'>;
    readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
    readonly walletAuthMethodStore: {
      listForWallet(input: { readonly walletId: string }): Promise<WalletAuthMethodRecord[]>;
    };
    readonly serverSeal: Pick<CloudflareD1EmailOtpServerSealRuntime, 'removeEmailOtpServerSeal'>;
  };
  /** The canonical add-auth-method service the linked finalize reuses. */
  readonly walletAuthMethods: {
    finalizeWalletAddAuthMethod(
      command: FinalizeWalletAddAuthMethodCommand,
      atomicCompanionStatements: readonly D1PreparedStatementLike[],
    ): Promise<WalletAddAuthMethodFinalizeResponse>;
    revokeWalletAuthMethodForOwnerSessionV1(input: {
      readonly walletId: import('@shared/utils/domainIds').WalletId;
      readonly walletAuthMethodId: import('@shared/utils/domainIds').WalletAuthMethodId;
      readonly requestedAtMs: number;
    }): Promise<{ readonly kind: 'applied' | 'replayed' | 'conflict' }>;
  };
  readonly authorizationService: Pick<
    AuthorizationService,
    | 'getLinkedDeviceWalletSessionStatus'
    | 'issueLinkedDeviceWalletSession'
    | 'readLinkedDeviceWalletSessionAuthorization'
    | 'renewLinkedDeviceWalletSession'
    | 'revokeLinkedDeviceWalletSession'
  >;
}): D1LinkedDeviceCompositionAssembly {
  const config = input.options.linkedDevice;
  if (!config) return {};

  const scope = {
    namespace: input.options.namespace,
    orgId: input.options.orgId,
    projectId: input.options.projectId,
    envId: input.options.envId,
  };
  const credentials = createD1LinkedDeviceCredentialResolverV1({
    database: input.options.database,
    scope,
  });
  const linkedOwnerAuthBindings = new D1LinkedDeviceOwnerAuthBindingStoreV1({
    database: input.options.database,
    scope,
  });
  const linkedDeviceExecution = new D1LinkedDeviceExecutionAdmissionResolverV1({
    database: input.options.database,
    scope,
    authorization: input.authorization,
    credentials,
    ownerAuthBindings: linkedOwnerAuthBindings,
    nowV1: config.execution.nowV1,
  });
  const linkedDeviceLocalPresence = createD1LinkedDeviceLocalPresenceVerifierV1({
    database: input.options.database,
    scope,
    rpId: config.execution.rpId,
    expectedOrigin: config.execution.expectedOrigin,
    logger: config.execution.logger,
    nowMs: config.execution.nowV1,
  });

  let deviceLinking: RouterApiServiceBag['deviceLinking'];
  let deviceManagement: RouterApiServiceBag['deviceManagement'];
  let laneRuntime: ReturnType<typeof createD1LinkedDeviceLaneRuntimeV1> | undefined;
  let ownerAuthorizationRoute: RouterApiServiceBag['deviceLinkingOwnerAuthorization'];
  let ownerRequestAuthenticator:
    | ReturnType<typeof createDeviceLinkingOwnerRequestAuthenticatorV1>
    | undefined;
  if (config.session) {
    const tenantId = parseTenantId(input.options.orgId);
    if (!tenantId.ok) {
      throw new Error(
        `orgId cannot identify a linked-device authorization tenant: ${tenantId.error.message}`,
      );
    }
    const ownerMetadata = new D1LinkedDeviceOwnerPlanningSnapshotStoreV1({
      database: input.options.database,
      scope,
      walletRegistration: input.walletRegistration,
      nowV1: config.execution.nowV1,
    });
    const ownerPlanningWriter = new D1LinkedDeviceOwnerPlanningSnapshotWriterV1({
      snapshotStore: ownerMetadata,
      walletRegistration: input.walletRegistration,
      deployment: new D1LinkedDeviceOwnerPlanningDeploymentV1({
        walletSource: input.walletStore,
      }),
    });
    const ownerAuthorizationProvider = createD1LinkedDeviceOwnerAuthorizationProviderV1({
      walletRegistration: input.walletRegistration,
      metadata: ownerMetadata,
      targetPlanner: {
        targetDeploymentDescriptorProvider: config.session.targetDeploymentDescriptorProvider,
      },
      planningWriter: ownerPlanningWriter,
      nowV1: config.execution.nowV1,
    });
    ownerRequestAuthenticator = createDeviceLinkingOwnerRequestAuthenticatorV1({
      authorizationSessions: input.authorizationSessions,
      nowV1: config.execution.nowV1,
    });
    ownerAuthorizationRoute = ownerAuthorizationProvider.ownerAuthorizationRoute;
    const sourceHandoff = new D1LinkedDeviceSourceHandoffProviderV1({
      database: input.options.database,
      scope,
    });
    laneRuntime = createD1LinkedDeviceLaneRuntimeV1({
      database: input.options.database,
      scope,
      nowV1: config.execution.nowV1,
      walletRegistration: input.walletRegistration,
      authenticateOwnerRequestV1: ownerRequestAuthenticator,
      ...config.session.laneRuntime,
    });
    const laneStoreOptions = {
      database: input.options.database,
      scope,
      now: config.execution.nowV1,
    };
    const laneLifecycleStore = new CloudflareD1LaneLifecycleStore(laneStoreOptions);
    const laneGateway = new CloudflareD1LaneEnrollmentGateway({
      lifecycleStore: laneLifecycleStore,
    });
    const laneLifecycle = createCloudflareD1LaneLifecycleApplicationService({
      ...laneStoreOptions,
      ...laneRuntime.laneLifecycle,
    });
    let emailOtpTargetFactor: D1LinkedDeviceEmailOtpTargetFactorV1 | undefined;
    let emailOtpRegistrationPort:
      | ReturnType<typeof createLinkedDeviceEmailOtpRegistrationPortV1>
      | undefined;
    if (input.emailOtpLinkedDevice) {
      const linkedEmailOtpGrants = new D1LinkedDeviceEmailOtpGrantStoreV1({
        database: input.options.database,
        scope,
      });
      emailOtpTargetFactor = new D1LinkedDeviceEmailOtpTargetFactorV1({
        issuer: input.emailOtpLinkedDevice.issuer,
        verifier: input.emailOtpLinkedDevice.verifier,
        enrollments: input.emailOtpLinkedDevice.enrollments,
        walletAuthMethods: input.emailOtpLinkedDevice.walletAuthMethodStore,
        serverSeal: input.emailOtpLinkedDevice.serverSeal,
        grants: linkedEmailOtpGrants,
      });
      emailOtpRegistrationPort = createLinkedDeviceEmailOtpRegistrationPortV1({
        grants: linkedEmailOtpGrants,
        bindingWriter: linkedOwnerAuthBindings,
        resolveBaseEmailOtpFactorV1:
          emailOtpTargetFactor.resolveBaseEmailOtpFactorForCompletionV1(),
        tenantId: tenantId.value,
      });
    }
    const targetCredential = new D1LinkedDeviceTargetCredentialProviderV1({
      database: input.options.database,
      scope,
      verifier: new LinkedDeviceWebAuthnRegistrationVerifierV1({
        expectedOrigin: config.execution.expectedOrigin,
      }),
      ...(emailOtpRegistrationPort === undefined
        ? {}
        : { emailOtpGrants: emailOtpRegistrationPort }),
      planner: ownerAuthorizationProvider.targetPlanner,
      sourceHandoff,
    });
    const provisioning = new D1LinkedDeviceProvisioningProviderV1({
      database: input.options.database,
      scope,
      execution: createLinkedDeviceR102ProvisioningExecutionV1({
        sourcePreparation: sourceHandoff,
        gateway: laneGateway,
        lifecycle: laneLifecycle,
        products: laneLifecycleStore,
      }),
    });
    deviceLinking = createD1LinkedDeviceRouteServiceV1({
      database: input.options.database,
      scope,
      tenantId: tenantId.value,
      expectedOrigin: config.execution.expectedOrigin,
      walletAuthMethods: input.walletAuthMethods,
      authorizationService: input.authorizationService,
      ownerAuthorization: ownerAuthorizationProvider.ownerAuthorization,
      ownerEnrollmentCeremonies: input.ownerEnrollmentCeremonies,
      ...(emailOtpTargetFactor === undefined
        ? {}
        : {
            emailOtpBaseFactors: linkedDeviceEmailOtpBaseFactorReaderV1(emailOtpTargetFactor),
            emailOtpTargetFactor,
          }),
      authenticateOwnerRequestV1: ownerRequestAuthenticator,
      linkedDeviceLocalPresence,
      targetCredential,
      operatorRecovery: new D1LinkedDeviceOperatorRecoveryProviderV1(
        config.session.operatorRecovery,
      ),
      provisioning,
      sourceHandoff,
      nowV1: config.execution.nowV1,
    });
  }

  if (config.management) {
    const sessionConfig = config.session;
    if (!deviceLinking || !sessionConfig) {
      throw new Error('linked-device management requires linked-device session composition');
    }
    const managementTenantId = parseTenantId(input.options.orgId);
    if (!managementTenantId.ok) {
      throw new Error(
        `orgId cannot identify a linked-device management tenant: ${managementTenantId.error.message}`,
      );
    }
    const metadataSource = new D1LinkedDeviceWalletSessionAuthorizationMetadataSourceV1({
      database: input.options.database,
      scope,
    });
    const preparation = new D1LinkedDeviceRevocationPreparationV1(metadataSource);
    const metadata = new D1LinkedDeviceCanonicalOwnerAuthMetadataSourceV1({
      database: input.options.database,
      scope,
      tenantId: managementTenantId.value,
    });
    const managementProjection = new D1LinkedDeviceManagementStoreV1({
      database: input.options.database,
      scope,
      metadata,
    });
    const walletSessionRevocation = new AuthorizationServiceLinkedDeviceWalletSessionRevocationV1(
      input.authorizationService,
    );
    if (!laneRuntime) {
      throw new Error('linked-device management requires linked-device lane runtime');
    }
    const laneStoreOptions = {
      database: input.options.database,
      scope,
      now: config.execution.nowV1,
    };
    deviceManagement = createD1LinkedDeviceManagementRouteServiceV1({
      database: input.options.database,
      scope,
      metadata,
      preparation,
      aggregateRevocation: createCloudflareD1LaneAggregateRevocationApplicationService({
        ...laneStoreOptions,
        ...laneRuntime.laneLifecycle,
      }),
      ownerCredentialRevocation: new D1LinkedDeviceOwnerCredentialRevocationV1(
        input.walletAuthMethods,
      ),
      walletSessionRevocation,
      localStateInvalidation: new D1LinkedDeviceLocalStateInvalidationV1({
        projection: managementProjection,
      }),
      nowV1: config.execution.nowV1,
      authenticateOwnerRequestV1: requireOwnerRequestAuthenticator(ownerRequestAuthenticator),
    });
  }

  let deviceLinkingGateway: RouterApiServiceBag['deviceLinkingGateway'];
  if (config.gateway) {
    const laneLifecycle = new CloudflareD1LaneLifecycleStore({
      database: input.options.database,
      scope,
      now: config.execution.nowV1,
    });
    deviceLinkingGateway = createD1LinkedDeviceGatewayCompletionServiceV1({
      database: input.options.database,
      scope,
      ownerAuthorization: config.gateway.ownerAuthorization,
      ownerEnrollmentCeremonies: input.ownerEnrollmentCeremonies,
      laneLifecycle,
      nowV1: config.execution.nowV1,
      authenticateGatewayRequestV1: config.gateway.authenticateGatewayRequestV1,
    });
  }

  return {
    linkedDeviceExecution,
    linkedDeviceLocalPresence,
    ...(deviceLinking === undefined ? {} : { deviceLinking }),
    ...(deviceManagement === undefined ? {} : { deviceManagement }),
    ...(deviceLinkingGateway === undefined ? {} : { deviceLinkingGateway }),
    ...(ownerAuthorizationRoute === undefined
      ? {}
      : { deviceLinkingOwnerAuthorization: ownerAuthorizationRoute }),
    ...(laneRuntime === undefined
      ? {}
      : { deviceLinkingLaneGateway: laneRuntime.laneGatewayRoute }),
  };
}

function requireOwnerRequestAuthenticator(
  authenticator: ReturnType<typeof createDeviceLinkingOwnerRequestAuthenticatorV1> | undefined,
): ReturnType<typeof createDeviceLinkingOwnerRequestAuthenticatorV1> {
  if (!authenticator) {
    throw new Error('linked-device owner request authentication is not configured');
  }
  return authenticator;
}

class CloudflareD1SignedDelegateExecutor {
  private signerWasmState: SignerWasmRuntimeState = { signerWasmReady: false };
  private readonly logger = normalizeLogger();

  constructor(private readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions) {}

  async execute(input: ExecuteSignedDelegateRequest): Promise<ExecuteSignedDelegateResult> {
    const relayerAccount = this.options.relayerAccount;
    const relayerPrivateKey = this.options.relayerPrivateKey;
    const nearRpcUrl = this.options.nearRpcUrl;
    if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl) {
      return {
        ok: false,
        code: 'not_configured',
        error: 'Signed delegate execution is not configured on this server',
      };
    }

    try {
      const relayerPublicKey =
        this.options.relayerPublicKey || toPublicKeyStringFromSecretKey(relayerPrivateKey);
      return await executeSignedDelegateWithRelayer({
        nearClient: new MinimalNearClient(nearRpcUrl),
        relayerAccount,
        relayerPublicKey,
        hash: input.hash,
        signedDelegate: input.signedDelegate,
        policy: input.policy,
        signGasRelayerNearTransaction: this.signGasRelayerNearTransaction.bind(this),
      });
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'delegate_execution_failed',
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  private async ensureSignerWasm(): Promise<void> {
    this.signerWasmState = await ensureSignerWasmRuntime({
      state: this.signerWasmState,
      override: this.options.signerWasmModuleOrPath,
      logger: this.logger,
    });
  }

  private async signGasRelayerNearTransaction(input: {
    readonly receiverId: string;
    readonly nonce: string;
    readonly blockHash: string;
    readonly actions: ActionArgsWasm[];
  }): ReturnType<typeof signGasRelayerNearTransactionWithDeps> {
    const relayerAccount = this.options.relayerAccount;
    const relayerPrivateKey = this.options.relayerPrivateKey;
    if (!relayerAccount || !relayerPrivateKey) {
      throw new Error('Signed delegate relayer credentials are not configured');
    }
    return await signGasRelayerNearTransactionWithDeps({
      ...input,
      ensureSignerWasm: this.ensureSignerWasm.bind(this),
      relayerAccount,
      relayerPrivateKey,
    });
  }
}

function d1RouterApiErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

async function linkD1Identity(
  identityStore: IdentityStore,
  input: D1IdentityLinkInput,
): Promise<LinkIdentityResult> {
  try {
    return await identityStore.linkSubjectToUserId(input);
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: d1RouterApiErrorMessage(error) || 'Failed to link identity',
    };
  }
}

function createLazyStoreState(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiLazyStoreState {
  return {
    options,
    walletStore: null,
    walletAuthMethodStore: null,
    registrationCeremonyIntentStore: null,
  };
}

function getRegistrationCeremonyIntentStoreForState(
  state: CloudflareD1RouterApiLazyStoreState,
): CloudflareD1RegistrationCeremonyIntentStore {
  if (state.registrationCeremonyIntentStore) return state.registrationCeremonyIntentStore;
  state.registrationCeremonyIntentStore = new CloudflareD1RegistrationCeremonyIntentStore({
    kind: 'partitioned_d1',
    database: state.options.database,
    scope: {
      namespace: state.options.namespace,
      orgId: state.options.orgId,
      projectId: state.options.projectId,
      envId: state.options.envId,
    },
    keyPrefix: 'gateway-registration:',
  });
  return state.registrationCeremonyIntentStore;
}

function getWalletAuthMethodStoreForState(
  state: CloudflareD1RouterApiLazyStoreState,
): D1WalletAuthMethodStore {
  if (state.walletAuthMethodStore) return state.walletAuthMethodStore;
  state.walletAuthMethodStore = new D1WalletAuthMethodStore({
    database: state.options.database,
    namespace: state.options.namespace,
    orgId: state.options.orgId,
    projectId: state.options.projectId,
    envId: state.options.envId,
    ensureSchema: false,
  });
  return state.walletAuthMethodStore;
}

function getWalletStoreForState(state: CloudflareD1RouterApiLazyStoreState): D1WalletStore {
  if (state.walletStore) return state.walletStore;
  state.walletStore = new D1WalletStore({
    database: state.options.database,
    namespace: state.options.namespace,
    orgId: state.options.orgId,
    projectId: state.options.projectId,
    envId: state.options.envId,
    ensureSchema: false,
  });
  return state.walletStore;
}

function scopePrepareForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  sql: string,
  values: readonly unknown[],
): D1PreparedStatementLike {
  return options.database.prepare(sql).bind(...scopeValuesForOptions(options, values));
}

function scopeValuesForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  values: readonly unknown[],
): readonly unknown[] {
  return [options.namespace, options.orgId, options.projectId, options.envId, ...values];
}

async function fundImplicitNearAccountForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  input: FundImplicitNearAccountRequest,
): Promise<FundImplicitNearAccountResult> {
  if (!options.implicitNearAccountTestFundingEnabled) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Implicit NEAR account test funding is not enabled on this server',
    };
  }
  const relayerAccount = options.relayerAccount;
  const relayerPrivateKey = options.relayerPrivateKey;
  const nearRpcUrl = options.nearRpcUrl;
  const fundedAmountYocto = options.accountInitialBalance;
  if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl || !fundedAmountYocto) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Implicit NEAR account funding is not configured on this server',
    };
  }
  return await fundImplicitNearAccountWithRelayer({
    ...input,
    relayerAccount,
    relayerPrivateKey,
    relayerPublicKey: options.relayerPublicKey,
    nearRpcUrl,
    fundedAmountYocto,
  });
}

/**
 * Validates a persisted claim before it is trusted to skip a broadcast or to be
 * replayed. An invalid record makes the D1 read fail, which leaves the effect
 * uncertain and prevents any network action on unvalidated bytes.
 */
function parseSponsoredNearAccountSideEffectRecord(
  raw: unknown,
): RouterAbEd25519YaoRegistrationSideEffectRecordV1<
  AccountCreationResult,
  PreparedSponsoredNearAccountCreationV1
> | null {
  if (!isRecordValue(raw)) return null;
  const record = raw;
  if (record.operation !== 'finalize') return null;
  const requestFingerprint = parseSideEffectFingerprint(record.requestFingerprint);
  const preparedArtifactFingerprint = parseSideEffectFingerprint(
    record.preparedArtifactFingerprint,
  );
  if (requestFingerprint === null || preparedArtifactFingerprint === null) return null;
  if (!isNonNegativeSafeInteger(record.claimedAtMs)) return null;
  const prepared = parsePreparedSponsoredNearAccountCreation(record.prepared);
  if (prepared === null) return null;
  if (record.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'finalize',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: record.claimedAtMs,
      prepared,
    };
  }
  if (record.kind === 'router_ab_ed25519_yao_registration_side_effect_completion_v1') {
    if (!isNonNegativeSafeInteger(record.completedAtMs)) return null;
    const response = parseAccountCreationResult(record.response);
    if (response === null) return null;
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'finalize',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: record.claimedAtMs,
      completedAtMs: record.completedAtMs,
      prepared,
      response,
    };
  }
  return null;
}

function parseWalletRegistrationOperationPrepared(
  raw: unknown,
): D1WalletRegistrationOperationPreparedV1 | null {
  return isRecordValue(raw) && raw.kind === 'd1_wallet_registration_operation_prepared_v1'
    ? { kind: 'd1_wallet_registration_operation_prepared_v1' }
    : null;
}

type RegistrationEstablishedSessionIdentity = Pick<
  RegistrationEstablishedSession,
  'walletId' | 'authorizationId' | 'walletSessionId' | 'quotaId' | 'expiresAtMs'
>;

function hasOnlyKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(record).every((key) => allowed.has(key));
}

function parseOpaqueWalletSessionToken(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const token = raw.trim();
  return token.startsWith('wst_') && token.length > 20 ? token : null;
}

function parseRegistrationEstablishedEcdsaToken(
  raw: unknown,
): RegistrationEstablishedEcdsaSession | null {
  if (
    !isRecordValue(raw) ||
    !hasOnlyKeys(raw, [
      'walletSessionToken',
      'thresholdSessionId',
      'keyHandle',
      'runtimePolicyScope',
      'routerAbEcdsaDerivationNormalSigning',
    ])
  ) {
    return null;
  }
  try {
    const thresholdSessionId = parseThresholdEcdsaSessionId(raw.thresholdSessionId);
    if (!thresholdSessionId.ok) return null;
    const walletSessionToken = parseOpaqueWalletSessionToken(raw.walletSessionToken);
    if (!walletSessionToken) return null;
    const keyHandle = parseThresholdEcdsaKeyHandle(raw.keyHandle);
    const runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
    const routerAbEcdsaDerivationNormalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1(
      raw.routerAbEcdsaDerivationNormalSigning,
    );
    if (!routerAbEcdsaDerivationNormalSigning) return null;
    return {
      sessionKind: 'opaque',
      walletSessionToken,
      thresholdSessionId: thresholdSessionId.value,
      keyHandle,
      runtimePolicyScope,
      routerAbEcdsaDerivationNormalSigning,
    };
  } catch {
    return null;
  }
}

function parseRegistrationEstablishedEd25519Token(
  raw: unknown,
): RegistrationEstablishedEd25519Session | null {
  if (
    !isRecordValue(raw) ||
    !hasOnlyKeys(raw, [
      'walletSessionToken',
      'thresholdSessionId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'runtimePolicyScope',
      'routerAbNormalSigning',
    ])
  ) {
    return null;
  }
  try {
    const thresholdSessionId = parseThresholdEd25519SessionId(raw.thresholdSessionId);
    if (!thresholdSessionId.ok) return null;
    const walletSessionToken = parseOpaqueWalletSessionToken(raw.walletSessionToken);
    if (!walletSessionToken) return null;
    const implicitNearAccountId = parseImplicitNearAccountId(raw.nearAccountId);
    const namedNearAccountId = parseNamedNearAccountId(raw.nearAccountId);
    const nearAccountId = implicitNearAccountId.ok
      ? implicitNearAccountId.value
      : namedNearAccountId.ok
        ? namedNearAccountId.value
        : null;
    if (!nearAccountId) return null;
    const nearEd25519SigningKeyId = parseNearEd25519SigningKeyId(raw.nearEd25519SigningKeyId);
    const runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
    const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
    if (!routerAbNormalSigning) return null;
    return {
      sessionKind: 'opaque',
      walletSessionToken,
      thresholdSessionId: thresholdSessionId.value,
      nearAccountId,
      nearEd25519SigningKeyId,
      runtimePolicyScope,
      routerAbNormalSigning,
    };
  } catch {
    return null;
  }
}

function parseRegistrationEstablishedSessionForD1(
  raw: unknown,
  expectedWalletId: RegistrationEstablishedSession['walletId'],
): RegistrationEstablishedSession | null {
  if (
    !isRecordValue(raw) ||
    !hasOnlyKeys(raw, [
      'kind',
      'walletId',
      'authorizationId',
      'walletSessionId',
      'quotaId',
      'expiresAtMs',
      'remainingUses',
      'tokens',
    ])
  ) {
    return null;
  }
  if (raw.kind !== 'registration_established_wallet_session_v1') {
    return null;
  }
  const walletId = parseWalletId(raw.walletId);
  const authorizationId = parseWalletSessionAuthorizationId(raw.authorizationId);
  const walletSessionId = parseWalletSessionId(raw.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(raw.quotaId);
  if (
    !walletId.ok ||
    walletId.value !== expectedWalletId ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    new Set([authorizationId.value, walletSessionId.value, quotaId.value]).size !== 3
  ) {
    return null;
  }
  if (
    typeof raw.expiresAtMs !== 'number' ||
    !Number.isSafeInteger(raw.expiresAtMs) ||
    raw.expiresAtMs <= 0 ||
    typeof raw.remainingUses !== 'number' ||
    !Number.isSafeInteger(raw.remainingUses) ||
    raw.remainingUses <= 0
  ) {
    return null;
  }
  const identity: RegistrationEstablishedSessionIdentity = {
    walletId: walletId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    expiresAtMs: raw.expiresAtMs,
  };
  if (!isRecordValue(raw.tokens) || typeof raw.tokens.kind !== 'string') {
    return null;
  }
  let tokens: RegistrationEstablishedSession['tokens'];
  if (raw.tokens.kind === 'evm_family_ecdsa') {
    if (!hasOnlyKeys(raw.tokens, ['kind', 'ecdsa'])) {
      return null;
    }
    const ecdsa = parseRegistrationEstablishedEcdsaToken(raw.tokens.ecdsa);
    if (!ecdsa) {
      return null;
    }
    tokens = { kind: 'evm_family_ecdsa', ecdsa };
  } else if (raw.tokens.kind === 'near_ed25519') {
    if (!hasOnlyKeys(raw.tokens, ['kind', 'ed25519'])) {
      return null;
    }
    const ed25519 = parseRegistrationEstablishedEd25519Token(raw.tokens.ed25519);
    if (!ed25519) {
      return null;
    }
    tokens = { kind: 'near_ed25519', ed25519 };
  } else if (raw.tokens.kind === 'near_ed25519_and_evm_family_ecdsa') {
    if (!hasOnlyKeys(raw.tokens, ['kind', 'ecdsa', 'ed25519'])) {
      return null;
    }
    const ecdsa = parseRegistrationEstablishedEcdsaToken(raw.tokens.ecdsa);
    const ed25519 = parseRegistrationEstablishedEd25519Token(raw.tokens.ed25519);
    if (!ecdsa || !ed25519) {
      return null;
    }
    tokens = { kind: 'near_ed25519_and_evm_family_ecdsa', ecdsa, ed25519 };
  } else {
    return null;
  }
  return {
    kind: 'registration_established_wallet_session_v1',
    ...identity,
    remainingUses: raw.remainingUses,
    tokens,
  };
}

/**
 * Refactor 94C. The activate operation row. Same record shape as the
 * finalize journal it absorbs, tagged with its own operation so an activate
 * row can never be read as a finalize row or vice versa.
 */
/**
 * The activate terminal response is the finalize commit merged with the
 * activation receipt and derivation bootstrap. Validating the commit half
 * through the existing parser keeps one definition of that shape; the
 * activation half must simply be present, since a stored response missing it
 * could not bring a wallet online and is not a usable replay.
 */
function parseD1WalletRegistrationActivateTerminalResponse(
  raw: unknown,
): WalletRegistrationActivateResponseV2 | null {
  /* The Ed25519-only pending terminal is not a finalize response: it has no
     signer, resolved account, or key identity, because none exist yet. It
     round-trips as itself, so a pending replay returns what was stored rather
     than a degraded parse. */
  if (
    isRecordValue(raw) &&
    raw.ok === true &&
    raw.kind === 'near_ed25519' &&
    isRecordValue(raw.nearProvisioning) &&
    raw.nearProvisioning.status === 'near_pending'
  ) {
    return raw as unknown as WalletRegistrationActivateResponseV2;
  }
  const commit = parseD1WalletRegistrationFinalizeTerminalResponse(raw);
  if (!commit) {
    return null;
  }
  if (!commit.ok) return commit;
  if (commit.kind !== 'evm_family_ecdsa' || !isRecordValue(raw)) {
    return null;
  }
  const stored = isRecordValue(raw.ecdsa) ? raw.ecdsa : null;
  if (!stored || !isRecordValue(stored.bootstrap)) {
    return null;
  }
  const registrationEstablishedSession = parseRegistrationEstablishedSessionForD1(
    raw.registrationEstablishedSession,
    commit.walletId,
  );
  if (!registrationEstablishedSession) {
    return null;
  }
  let activation: ReturnType<typeof parseRouterAbEcdsaRegistrationActivationReceiptV1>;
  try {
    activation = parseRouterAbEcdsaRegistrationActivationReceiptV1(stored.activation);
  } catch {
    return null;
  }
  const bootstrap = parseD1EcdsaDerivationServerBootstrapResponse(stored.bootstrap);
  if (!bootstrap) {
    return null;
  }
  return {
    ...commit,
    registrationEstablishedSession,
    ecdsa: {
      ...commit.ecdsa,
      activation,
      /* The bootstrap is the Gateway's own derivation payload, written by
         this service and never client-supplied; there is no separate parser
         for it, so presence is the check. */
      bootstrap,
    },
  };
}

function parseWalletRegistrationActivateSideEffectRecord(
  raw: unknown,
): D1WalletRegistrationActivateSideEffectRecord | null {
  if (
    !isRecordValue(raw) ||
    raw.operation !== 'registration_activate' ||
    !isNonNegativeSafeInteger(raw.claimedAtMs)
  ) {
    return null;
  }
  const requestFingerprint = parseSideEffectFingerprint(raw.requestFingerprint);
  const preparedArtifactFingerprint = parseSideEffectFingerprint(raw.preparedArtifactFingerprint);
  const prepared = parseWalletRegistrationOperationPrepared(raw.prepared);
  if (requestFingerprint === null || preparedArtifactFingerprint === null || prepared === null) {
    return null;
  }
  if (raw.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'registration_activate',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: raw.claimedAtMs,
      prepared,
    };
  }
  if (
    raw.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v1' ||
    !isNonNegativeSafeInteger(raw.completedAtMs)
  ) {
    return null;
  }
  const response = parseD1WalletRegistrationActivateTerminalResponse(raw.response);
  if (!response) return null;
  return {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
    operation: 'registration_activate',
    requestFingerprint,
    preparedArtifactFingerprint,
    claimedAtMs: raw.claimedAtMs,
    completedAtMs: raw.completedAtMs,
    prepared,
    response,
  };
}

/**
 * Deferred NEAR provisioning's own operation row. Same record shape as the
 * finalize journal it replaces for this route, tagged with its own operation
 * so a provisioning row can never be read as an activate or finalize row.
 */
function parseWalletRegistrationNearProvisioningSideEffectRecord(
  raw: unknown,
): D1WalletRegistrationNearProvisioningSideEffectRecord | null {
  if (
    !isRecordValue(raw) ||
    raw.operation !== 'near_provisioning' ||
    !isNonNegativeSafeInteger(raw.claimedAtMs)
  ) {
    return null;
  }
  const requestFingerprint = parseSideEffectFingerprint(raw.requestFingerprint);
  const preparedArtifactFingerprint = parseSideEffectFingerprint(raw.preparedArtifactFingerprint);
  const prepared = parseWalletRegistrationOperationPrepared(raw.prepared);
  if (requestFingerprint === null || preparedArtifactFingerprint === null || prepared === null) {
    return null;
  }
  if (raw.kind === 'router_ab_ed25519_yao_registration_side_effect_claim_v1') {
    return {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'near_provisioning',
      requestFingerprint,
      preparedArtifactFingerprint,
      claimedAtMs: raw.claimedAtMs,
      prepared,
    };
  }
  if (
    raw.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v1' ||
    !isNonNegativeSafeInteger(raw.completedAtMs)
  ) {
    return null;
  }
  const response = parseD1WalletRegistrationFinalizeTerminalResponse(raw.response);
  if (!response) return null;
  return {
    kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
    operation: 'near_provisioning',
    requestFingerprint,
    preparedArtifactFingerprint,
    claimedAtMs: raw.claimedAtMs,
    completedAtMs: raw.completedAtMs,
    prepared,
    response,
  };
}

function parsePreparedSponsoredNearAccountCreation(
  value: unknown,
): PreparedSponsoredNearAccountCreationV1 | null {
  if (!isRecordValue(value) || value.kind !== 'prepared_sponsored_near_account_creation_v1') {
    return null;
  }
  const accountId = parseNonEmptyString(value.accountId);
  const publicKey = parseNonEmptyString(value.publicKey);
  const relayerAccountId = parseNonEmptyString(value.relayerAccountId);
  const relayerPublicKey = parseNonEmptyString(value.relayerPublicKey);
  const initialBalanceYocto = parseNonEmptyString(value.initialBalanceYocto);
  const transactionHash = parseNonEmptyString(value.transactionHash);
  const nextNonce = parseNonEmptyString(value.nextNonce);
  const blockHash = parseNonEmptyString(value.blockHash);
  const signedTransactionBorshB64u = parseBoundedBase64Url(value.signedTransactionBorshB64u);
  if (
    accountId === null ||
    publicKey === null ||
    relayerAccountId === null ||
    relayerPublicKey === null ||
    initialBalanceYocto === null ||
    transactionHash === null ||
    nextNonce === null ||
    blockHash === null ||
    signedTransactionBorshB64u === null
  ) {
    return null;
  }
  return {
    kind: 'prepared_sponsored_near_account_creation_v1',
    accountId,
    publicKey,
    relayerAccountId,
    relayerPublicKey,
    initialBalanceYocto,
    transactionHash,
    nextNonce,
    blockHash,
    signedTransactionBorshB64u,
  };
}

function parseAccountCreationResult(value: unknown): AccountCreationResult | null {
  if (!isRecordValue(value) || typeof value.success !== 'boolean') return null;
  const accountId = parseOptionalString(value.accountId);
  const transactionHash = parseOptionalString(value.transactionHash);
  const error = parseOptionalString(value.error);
  const message = parseOptionalString(value.message);
  if (
    ('accountId' in value && accountId === null) ||
    ('transactionHash' in value && transactionHash === null) ||
    ('error' in value && error === null) ||
    ('message' in value && message === null)
  ) {
    return null;
  }
  if (value.success && (accountId === undefined || transactionHash === undefined)) return null;
  const normalizedAccountId = accountId ?? undefined;
  const normalizedTransactionHash = transactionHash ?? undefined;
  const normalizedError = error ?? undefined;
  const normalizedMessage = message ?? undefined;
  return {
    success: value.success,
    ...(normalizedAccountId === undefined ? {} : { accountId: normalizedAccountId }),
    ...(normalizedTransactionHash === undefined
      ? {}
      : { transactionHash: normalizedTransactionHash }),
    ...(normalizedError === undefined ? {} : { error: normalizedError }),
    ...(normalizedMessage === undefined ? {} : { message: normalizedMessage }),
  };
}

function parseNonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function parseSideEffectFingerprint(value: unknown): string | null {
  return typeof value === 'string' && /^[a-zA-Z0-9:_-]{32,192}$/u.test(value) ? value : null;
}

function parseBoundedBase64Url(value: unknown): string | null {
  return typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 8_192 &&
    /^[\w-]+$/u.test(value)
    ? value
    : null;
}

function parseOptionalString(value: unknown): string | undefined | null {
  return value === undefined ? undefined : parseNonEmptyString(value);
}

function isNonNegativeSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function resolveEd25519YaoProductRegistration(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): RouterAbEd25519YaoProductRegistrationRuntimeV1 | null {
  return options.ed25519YaoProductRegistration || null;
}

function sponsoredNearAccountSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): RouterAbEd25519YaoRegistrationSideEffectStoreV1<
  AccountCreationResult,
  PreparedSponsoredNearAccountCreationV1
> {
  return createCloudflareD1VersionedJsonRecordStore<
    RouterAbEd25519YaoRegistrationSideEffectRecordV1<
      AccountCreationResult,
      PreparedSponsoredNearAccountCreationV1
    >
  >({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'router-ab-yao-sponsored-account:',
    encode: (value) => value as unknown as VersionedJsonObject,
    parse: parseSponsoredNearAccountSideEffectRecord,
  });
}

function walletRegistrationActivateSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletRegistrationActivateSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletRegistrationActivateSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-registration-activate:',
    encode: (value) => value as unknown as VersionedJsonObject,
    parse: parseWalletRegistrationActivateSideEffectRecord,
  });
}

function walletRegistrationNearProvisioningSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletRegistrationNearProvisioningSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletRegistrationNearProvisioningSideEffectRecord>(
    {
      database: options.database,
      scope: {
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
      },
      keyPrefix: 'wallet-registration-near-provisioning:',
      encode: (value) => value as unknown as VersionedJsonObject,
      parse: parseWalletRegistrationNearProvisioningSideEffectRecord,
    },
  );
}

function walletAddSignerStartSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletAddSignerStartSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletAddSignerStartSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-add-signer-start:',
    encode: (value) => value as unknown as VersionedJsonObject,
    parse: parseD1WalletAddSignerStartSideEffectRecord,
  });
}

function walletAddSignerFinalizeSideEffectStore(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
): D1WalletAddSignerFinalizeSideEffectStore {
  return createCloudflareD1VersionedJsonRecordStore<D1WalletAddSignerFinalizeSideEffectRecord>({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
    keyPrefix: 'wallet-add-signer-finalize:',
    encode: (value) => value as unknown as VersionedJsonObject,
    parse: parseD1WalletAddSignerFinalizeSideEffectRecord,
  });
}

/**
 * Creates the sponsored account through a durable claim. The signed transaction
 * and its hash are persisted before the broadcast, so a lost response replays
 * those exact bytes instead of building a second transaction under a fresh
 * nonce. Rebroadcasting an identical signed transaction reuses its hash, so the
 * network treats the retry as the same transaction.
 */
async function createSponsoredNamedNearAccountForOptions(
  options: NormalizedCloudflareD1RouterApiAuthServiceOptions,
  input: SponsoredNamedNearAccountInput,
): Promise<SponsoredNamedNearAccountCreationResult> {
  const relayerAccount = options.relayerAccount;
  const relayerPrivateKey = options.relayerPrivateKey;
  const nearRpcUrl = options.nearRpcUrl;
  const initialBalanceYocto = options.accountInitialBalance;
  if (!relayerAccount || !relayerPrivateKey || !nearRpcUrl || !initialBalanceYocto) {
    return {
      kind: 'rejected',
      message: 'Sponsored NEAR account creation is not configured on this server',
    };
  }
  const relayerInput = {
    accountId: input.accountId,
    publicKey: input.publicKey,
    relayerAccount,
    relayerPrivateKey,
    relayerPublicKey: options.relayerPublicKey,
    nearRpcUrl,
    initialBalanceYocto,
  };
  const requestFingerprint = base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        kind: 'sponsored_near_account_creation_v1',
        accountId: input.accountId,
        publicKey: input.publicKey,
        relayerAccountId: relayerAccount,
        initialBalanceYocto,
      }),
    ),
  );
  const outcome = await runRouterAbEd25519YaoRegistrationSideEffectV1<
    AccountCreationResult,
    PreparedSponsoredNearAccountCreationV1
  >(sponsoredNearAccountSideEffectStore(options), {
    kind: 'prepared_resumable',
    resumeAfterMs: 30_000,
    operation: 'finalize',
    key: `sponsored-account:${input.idempotencyKey}`,
    requestFingerprint,
    nowMs: () => Date.now(),
    prepare: async () => {
      const prepared = await prepareSponsoredNearAccountCreationWithRelayer(relayerInput);
      if (!prepared.ok) throw new Error(prepared.message);
      return prepared.prepared;
    },
    derivePreparedArtifactFingerprint: preparedSponsoredNearAccountCreationArtifactFingerprint,
    execute: async (prepared, attempt) => {
      if (!prepared) throw new Error('Sponsored NEAR account transaction was not prepared');
      const broadcast = await broadcastPreparedSponsoredNearAccountCreation({
        prepared,
        nearRpcUrl,
        relayerAccountId: relayerAccount,
        // A resumed attempt follows a broadcast whose outcome was never
        // observed, so settle it against the chain before resubmitting.
        reconcileFirst: attempt === 'resumed',
      });
      if (broadcast.kind === 'uncertain') {
        // Throwing keeps the claim open so a later retry reconciles. Returning
        // here would persist a possibly-landed transaction as a terminal failure.
        throw new Error(broadcast.message);
      }
      return broadcast.result;
    },
  });
  switch (outcome.kind) {
    case 'executed':
    case 'exact_replay': {
      if (outcome.value.success && outcome.value.accountId && outcome.value.transactionHash) {
        return {
          kind: 'created',
          accountId: outcome.value.accountId,
          transactionHash: outcome.value.transactionHash,
        };
      }
      return {
        kind: 'rejected',
        message:
          outcome.value.message ||
          outcome.value.error ||
          'Sponsored NEAR account creation was rejected',
      };
    }
    case 'in_progress':
    case 'uncertain': {
      const message =
        outcome.kind === 'uncertain'
          ? outcome.message
          : 'Sponsored NEAR account creation is already in progress for this registration';
      return { kind: 'retryable', message, retryAfterMs: 30_000 };
    }
    case 'request_conflict':
      return {
        kind: 'rejected',
        message: 'Sponsored NEAR account creation idempotency key conflicts with another request',
      };
  }
}

async function readD1Ed25519KeyManifestBySlot(
  walletStore: D1WalletStore,
  input: Parameters<D1WebAuthnWalletManifestSource['getEd25519KeyManifestBySlot']>[0],
): Promise<Awaited<ReturnType<D1WebAuthnWalletManifestSource['getEd25519KeyManifestBySlot']>>> {
  const signer = await walletStore.getEd25519SignerBySlot(input);
  return signer ? { custodyKeyManifestDigestB64u: signer.custodyKeyManifestDigestB64u } : null;
}

function createCloudflareD1RouterApiAuthAssembly(
  input: CloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiAuthAssembly {
  const options = normalizeD1RouterApiAuthOptions(input);
  const prepare: ScopedD1Prepare = scopePrepareForOptions.bind(undefined, options);
  const lazyStores = createLazyStoreState(options);
  const getRegistrationCeremonyIntentStore = getRegistrationCeremonyIntentStoreForState.bind(
    undefined,
    lazyStores,
  );
  const getWalletAuthMethodStore = getWalletAuthMethodStoreForState.bind(undefined, lazyStores);
  const getWalletStore = getWalletStoreForState.bind(undefined, lazyStores);
  const walletAuthMethodStore = getWalletAuthMethodStore();
  const walletStore = getWalletStore();
  const createSponsoredNamedNearAccount = createSponsoredNamedNearAccountForOptions.bind(
    undefined,
    options,
  );

  const identityStore = new D1IdentityStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
    ensureSchema: false,
  });
  const linkIdentity = linkD1Identity.bind(undefined, identityStore);
  const authorizationStore = new CloudflareD1AuthorizationStore({
    database: options.database,
    namespace: options.namespace,
    walletSignerScope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
  });
  const authorizationService = new AuthorizationService({
    policy: capabilityPolicyPort,
    sessions: authorizationStore,
    evidence: authorizationStore,
    grants: authorizationStore,
    authorizedOperations: authorizationStore,
    audit: authorizationStore,
  });
  const googleEmailOtpRegistrationAttempts = new CloudflareD1GoogleEmailOtpRegistrationAttemptStore(
    {
      prepare,
      orgId: options.orgId,
    },
  );
  const nearPublicKeys = new CloudflareD1NearPublicKeyStore({ prepare });
  const webAuthnStore = new CloudflareD1WebAuthnStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const webAuthnAuthService = new CloudflareD1WebAuthnAuthService({
    webAuthnStore,
    walletAuthMethodStore,
    walletManifestSource: {
      getEd25519KeyManifestBySlot: readD1Ed25519KeyManifestBySlot.bind(undefined, walletStore),
    },
  });
  const linkedDeviceWalletRegistrationProjection: Pick<
    RouterApiWalletRegistrationService,
    'resolveActiveOwnerWalletExecutionLane' | 'listWalletEcdsaCustodyContinuity'
  > = {
    resolveActiveOwnerWalletExecutionLane: resolveD1ActiveOwnerWalletExecutionLane.bind(
      undefined,
      new D1WalletExecutionLaneProjectionSource(walletAuthMethodStore, walletStore),
    ),
    listWalletEcdsaCustodyContinuity: walletStore.listEcdsaSignersForWallet.bind(walletStore),
  };
  const emailOtpChallenges = new CloudflareD1EmailOtpChallengeStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const emailOtpDelivery = new CloudflareD1EmailOtpDeliveryRuntime(options.emailOtp);
  const emailOtpEnrollments = new CloudflareD1EmailOtpEnrollmentStore({ prepare });
  const emailOtpGrants = new CloudflareD1EmailOtpGrantStore({ prepare });
  const emailOtpRateLimits = new CloudflareD1EmailOtpRateLimitStore({
    prepare,
    rateLimits: options.emailOtp.rateLimits,
  });
  const emailOtpServerSeal = new CloudflareD1EmailOtpServerSealRuntime(options.emailOtpServerSeal);
  const googleEmailOtpSessions = new CloudflareD1GoogleEmailOtpSessionResolver({
    emailOtpEnrollments,
    emailOtpRateLimits,
    identityStore,
    linkIdentity,
    production: options.emailOtp.production,
    registrationAttempts: googleEmailOtpRegistrationAttempts,
  });
  const identityService = new CloudflareD1IdentityService({
    accountIdDerivationSecret: options.accountIdDerivationSecret,
    identityStore,
    relayerAccount: options.relayerAccount,
    resolveGoogleEmailOtpSession: googleEmailOtpSessions.resolve.bind(googleEmailOtpSessions),
  });
  const oidcVerification = new CloudflareD1OidcVerificationService({
    googleOidcClientId: options.googleOidcClientId,
    githubOAuth: options.githubOAuth,
    identityStore,
    linkIdentity,
  });
  const emailOtpRegistrationEnrollmentFinalizer =
    new CloudflareD1EmailOtpRegistrationEnrollmentFinalizer({
      emailOtpEnrollments,
      googleEmailOtpSessions,
    });
  const emailOtpChallengeVerifier = new CloudflareD1EmailOtpChallengeVerifier({
    emailOtpChallenges,
    emailOtpEnrollments,
    emailOtpRateLimits,
    lockoutTtlMs: options.emailOtp.lockoutTtlMs,
  });
  /* The custody envelope store is shared by registration, unlock, recovery,
     and auth-method revocation; every route must address the same rows. */
  const passkeyCustodyEnvelopes = new CloudflareD1PasskeyCustodyEnvelopeStore({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
  });
  const authorizationTenantId = parseTenantId(options.orgId);
  if (!authorizationTenantId.ok) {
    throw new Error(
      `orgId cannot identify an authorization tenant: ${authorizationTenantId.error.message}`,
    );
  }
  const linkedDeviceOwnerAuthBindingStore = new D1LinkedDeviceOwnerAuthBindingStoreV1({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
  });
  const walletAuthMethods = new CloudflareD1WalletAuthMethodService({
    emailOtpChallengeVerifier,
    getRegistrationCeremonyIntentStore,
    getWalletAuthMethodStore,
    googleEmailOtpRegistrationAttempts,
    linkedDeviceOwnerAuthBindings: linkedDeviceOwnerAuthBindingStore,
    linkedDeviceOwnerAuthBindingStore,
    revokeOwnerWalletSessions: (sessionInput) =>
      authorizationService.revokeReusableWalletSessionsForAuthMethod({
        tenantId: authorizationTenantId.value,
        walletId: sessionInput.walletId,
        walletAuthMethodId: sessionInput.walletAuthMethodId,
        nowMs: sessionInput.requestedAtMs,
      }),
    passkeyCustodyEnvelopes,
    sha256Bytes: sha256BytesPortable,
    webAuthnStore,
  });
  const walletRegistrationCommitStore = new CloudflareD1WalletRegistrationCommitStore({
    database: options.database,
    namespace: options.namespace,
    orgId: options.orgId,
    projectId: options.projectId,
    envId: options.envId,
  });
  const walletCustodyCommitStore = new CloudflareD1WalletCustodyCommitStore({
    database: options.database,
    scope: {
      namespace: options.namespace,
      orgId: options.orgId,
      projectId: options.projectId,
      envId: options.envId,
    },
  });
  const signedDelegateExecutor = new CloudflareD1SignedDelegateExecutor(options);
  const walletRegistrations = new CloudflareD1WalletRegistrationService({
    authorizationService,
    authorizationTenantId: authorizationTenantId.value,
    createSponsoredNamedNearAccount,
    emailOtpRegistrationEnrollmentFinalizer,
    getRegistrationCeremonyIntentStore,
    getEd25519YaoProductRegistration: () => resolveEd25519YaoProductRegistration(options),
    ecdsaStrictRegistration: options.ecdsaStrictRegistration,
    getWalletStore,
    activateSideEffects: walletRegistrationActivateSideEffectStore(options),
    nearProvisioningSideEffects: walletRegistrationNearProvisioningSideEffectStore(options),
    walletRegistrationCommitStore,
    walletCustodyCommitStore,
    walletAuthMethods,
  });
  const walletAddSigners = new CloudflareD1WalletAddSignerService({
    getRegistrationCeremonyIntentStore,
    getEd25519YaoProductRegistration: () => resolveEd25519YaoProductRegistration(options),
    ecdsaStrictRegistration: options.ecdsaStrictRegistration,
    getWalletStore,
    walletAuthMethods,
    passkeyCustodyEnvelopes,
    startSideEffects: walletAddSignerStartSideEffectStore(options),
    finalizeSideEffects: walletAddSignerFinalizeSideEffectStore(options),
  });
  const registrationIntents = new CloudflareD1RegistrationIntentService({
    getRegistrationCeremonyIntentStore,
  });
  const emailOtpChallengeIssuer = new CloudflareD1EmailOtpChallengeIssuer({
    config: {
      challengeTtlMs: options.emailOtp.challengeTtlMs,
      codeLength: options.emailOtp.codeLength,
      maxActiveChallengesPerContext: options.emailOtp.maxActiveChallengesPerContext,
      maxAttempts: options.emailOtp.maxAttempts,
    },
    emailOtpChallenges,
    emailOtpDelivery,
    emailOtpEnrollments,
    emailOtpRateLimits,
  });
  const emailOtpChallengeService = new CloudflareD1EmailOtpChallengeService({
    challenges: emailOtpChallenges,
    devOutboxEnabled: options.emailOtp.devOutboxEnabled,
    finalizer: emailOtpRegistrationEnrollmentFinalizer,
    grantTtlMs: options.emailOtp.grantTtlMs,
    grants: emailOtpGrants,
    issuer: emailOtpChallengeIssuer,
    registrationAttempts: googleEmailOtpRegistrationAttempts,
    verifier: emailOtpChallengeVerifier,
  });
  const emailOtpRecoveryService = new CloudflareD1EmailOtpRecoveryService({
    challengeVerifier: emailOtpChallengeVerifier,
    emailOtpChallenges,
    emailOtpEnrollments,
    emailOtpGrants,
    emailOtpRateLimits,
    grantTtlMs: options.emailOtp.grantTtlMs,
  });
  // Composed after the R100 Email OTP pieces so the linked-device Email OTP
  // target factor reuses this deployment's exact issuer, verifier, enrollment
  // store, and server-seal runtime — never a second OTP implementation.
  const linkedDeviceComposition = createD1LinkedDeviceComposition({
    ownerEnrollmentCeremonies: getRegistrationCeremonyIntentStore(),
    emailOtpLinkedDevice: {
      issuer: emailOtpChallengeIssuer,
      verifier: emailOtpChallengeVerifier,
      enrollments: emailOtpEnrollments,
      walletAuthMethodStore,
      serverSeal: emailOtpServerSeal,
    },
    walletAuthMethods: {
      finalizeWalletAddAuthMethod: (command, atomicCompanionStatements) =>
        walletAuthMethods.finalizeWalletAddAuthMethod(command, atomicCompanionStatements),
      revokeWalletAuthMethodForOwnerSessionV1: (command) =>
        walletAuthMethods.revokeWalletAuthMethodForOwnerSessionV1(command),
    },
    options,
    authorizationSessions: createD1AuthorizationSessionRouteService({
      authorizationService,
      options,
    }),
    walletStore,
    walletRegistration: linkedDeviceWalletRegistrationProjection,
    authorization: authorizationStore,
    authorizationService,
  });

  return {
    options,
    emailOtpServerSeal,
    emailOtpChallengeService,
    emailOtpRecoveryService,
    identityService,
    oidcVerification,
    authorizationService,
    googleEmailOtpSessions,
    nearPublicKeys,
    webAuthnAuthService,
    walletAuthMethods,
    walletRegistrations,
    walletAuthMethodStore,
    walletStore,
    walletAddSigners,
    registrationIntents,
    signedDelegateExecutor,
    passkeyCustodyEnvelopes,
    walletCustodyCommitStore,
    webAuthnStore,
    ...linkedDeviceComposition,
  };
}

class D1WalletExecutionLaneProjectionSource implements WalletExecutionLaneProjectionSource {
  constructor(
    private readonly walletAuthMethodStore: D1WalletAuthMethodStore,
    private readonly walletStore: D1WalletStore,
  ) {}

  async listWalletAuthMethods(
    input: Parameters<WalletExecutionLaneProjectionSource['listWalletAuthMethods']>[0],
  ) {
    return await this.walletAuthMethodStore.listForWallet({ walletId: input.walletId });
  }

  async listWalletSigners(
    input: Parameters<WalletExecutionLaneProjectionSource['listWalletSigners']>[0],
  ) {
    const [ed25519, ecdsa] = await Promise.all([
      this.walletStore.listEd25519SignersForWallet({ walletId: input.walletId }),
      this.walletStore.listEcdsaSignersForWallet({ walletId: input.walletId }),
    ]);
    return [...ed25519, ...ecdsa];
  }
}

async function resolveD1ActiveOwnerWalletExecutionLane(
  source: WalletExecutionLaneProjectionSource,
  input: Parameters<
    RouterApiServiceBag['walletRegistration']['resolveActiveOwnerWalletExecutionLane']
  >[0],
): Promise<WalletExecutionLaneProjectionResult> {
  let walletAuthMethodId;
  switch (input.authorization.kind) {
    case 'wallet_auth_method':
      walletAuthMethodId = input.authorization.walletAuthMethodId;
      break;
    case 'authority_ref': {
      const authMethods = await source.listWalletAuthMethods({ walletId: input.walletId });
      walletAuthMethodId = await resolveWalletAuthMethodIdForAuthority({
        walletId: input.walletId,
        authorityRef: input.authorization.authorityRef,
        authSource: input.authorization.authSource,
        authMethods,
      });
      if (!walletAuthMethodId) return { kind: 'refused', reason: 'auth_method_missing' };
      break;
    }
  }
  return await resolveActiveOwnerWalletExecutionLane({
    source,
    walletId: input.walletId,
    walletAuthMethodId,
    expectedMaterialActivation: input.expectedMaterialActivation,
  });
}

function createD1WalletRegistrationRouteService(
  assembly: D1WalletRegistrationRouteServiceAssembly,
): RouterApiServiceBag['walletRegistration'] {
  const laneProjectionSource = new D1WalletExecutionLaneProjectionSource(
    assembly.walletAuthMethodStore,
    assembly.walletStore,
  );
  return {
    resolveActiveOwnerWalletExecutionLane: resolveD1ActiveOwnerWalletExecutionLane.bind(
      undefined,
      laneProjectionSource,
    ),
    listWalletEcdsaCustodyContinuity:
      assembly.walletRegistrations.listWalletEcdsaCustodyContinuity.bind(
        assembly.walletRegistrations,
      ),
    resolveEd25519MaterialActivation:
      assembly.walletRegistrations.resolveEd25519MaterialActivation.bind(
        assembly.walletRegistrations,
      ),
    resolveEcdsaMaterialActivation:
      assembly.walletRegistrations.resolveEcdsaMaterialActivation.bind(
        assembly.walletRegistrations,
      ),
    listWalletEcdsaKeyFactsInventory:
      assembly.walletRegistrations.listWalletEcdsaKeyFactsInventory.bind(
        assembly.walletRegistrations,
      ),
    readActiveEmailOtpEnrollment:
      assembly.emailOtpRecoveryService.readActiveEmailOtpEnrollment.bind(
        assembly.emailOtpRecoveryService,
      ),
    setupWalletRegistration: assembly.walletRegistrations.setupWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    respondWalletRegistration: assembly.walletRegistrations.respondWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    activateWalletRegistration: assembly.walletRegistrations.activateWalletRegistration.bind(
      assembly.walletRegistrations,
    ),
    completeWalletRegistrationNearProvisioning:
      assembly.walletRegistrations.completeWalletRegistrationNearProvisioning.bind(
        assembly.walletRegistrations,
      ),
    refreshEd25519YaoWalletSession:
      assembly.walletRegistrations.refreshEd25519YaoWalletSession.bind(
        assembly.walletRegistrations,
      ),
    provisionEd25519YaoWalletSession:
      assembly.walletRegistrations.provisionEd25519YaoWalletSession.bind(
        assembly.walletRegistrations,
      ),
    recordEcdsaPostRegistrationProof:
      assembly.walletRegistrations.recordEcdsaPostRegistrationProof.bind(
        assembly.walletRegistrations,
      ),
    activateEcdsaPostRegistrationSession:
      assembly.walletRegistrations.activateEcdsaPostRegistrationSession.bind(
        assembly.walletRegistrations,
      ),
  };
}

function createD1WalletAuthMethodRouteService(
  assembly: D1WalletAuthMethodRouteServiceAssembly,
): RouterApiServiceBag['walletAuthMethods'] {
  return {
    verifyActivePasskeyAuthority: assembly.walletAuthMethods.verifyActivePasskeyAuthority.bind(
      assembly.walletAuthMethods,
    ),
    verifyActiveEmailOtpAuthority: assembly.walletAuthMethods.verifyActiveEmailOtpAuthority.bind(
      assembly.walletAuthMethods,
    ),
    resolveActiveEmailOtpAuthorityForVerifiedSubject:
      assembly.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject.bind(
        assembly.walletAuthMethods,
      ),
    createAddAuthMethodIntent: assembly.registrationIntents.createAddAuthMethodIntent.bind(
      assembly.registrationIntents,
    ),
    createAddSignerIntent: assembly.registrationIntents.createAddSignerIntent.bind(
      assembly.registrationIntents,
    ),
    finalizeWalletAddAuthMethod: assembly.walletAuthMethods.finalizeWalletAddAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    finalizeWalletAddSigner: assembly.walletAddSigners.finalizeWalletAddSigner.bind(
      assembly.walletAddSigners,
    ),
    respondWalletAddSignerEcdsaDerivation:
      assembly.walletAddSigners.respondWalletAddSignerEcdsaDerivation.bind(
        assembly.walletAddSigners,
      ),
    activateWalletAddSignerEcdsa: assembly.walletAddSigners.activateWalletAddSignerEcdsa.bind(
      assembly.walletAddSigners,
    ),
    getWalletAddSignerRuntimePolicyScope:
      assembly.walletAddSigners.getWalletAddSignerRuntimePolicyScope.bind(
        assembly.walletAddSigners,
      ),
    revokeWalletAuthMethod: assembly.walletAuthMethods.revokeWalletAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    startWalletAddAuthMethod: assembly.walletAuthMethods.startWalletAddAuthMethod.bind(
      assembly.walletAuthMethods,
    ),
    startWalletAddSigner: assembly.walletAddSigners.startWalletAddSigner.bind(
      assembly.walletAddSigners,
    ),
  };
}

function createD1WalletUnlockRouteService(
  assembly: D1WalletUnlockRouteServiceAssembly,
): RouterApiServiceBag['walletUnlock'] {
  return {
    createEmailOtpUnlockChallenge:
      assembly.emailOtpRecoveryService.createEmailOtpUnlockChallenge.bind(
        assembly.emailOtpRecoveryService,
      ),
    createWebAuthnLoginOptions: assembly.webAuthnAuthService.createWebAuthnLoginOptions.bind(
      assembly.webAuthnAuthService,
    ),
    markEmailOtpStrongAuthSatisfied:
      assembly.emailOtpRecoveryService.markEmailOtpStrongAuthSatisfied.bind(
        assembly.emailOtpRecoveryService,
      ),
    verifyEmailOtpUnlockProof: assembly.emailOtpRecoveryService.verifyEmailOtpUnlockProof.bind(
      assembly.emailOtpRecoveryService,
    ),
    verifyWebAuthnLogin: assembly.webAuthnAuthService.verifyWebAuthnLogin.bind(
      assembly.webAuthnAuthService,
    ),
  };
}

function createD1EmailOtpRouteService(
  assembly: D1EmailOtpRouteServiceAssembly,
): RouterApiServiceBag['emailOtp'] {
  return {
    applyEmailOtpServerSeal: assembly.emailOtpServerSeal.applyEmailOtpServerSeal.bind(
      assembly.emailOtpServerSeal,
    ),
    cleanupGoogleEmailOtpDevRegistrationState:
      assembly.googleEmailOtpSessions.cleanupDevRegistrationState.bind(
        assembly.googleEmailOtpSessions,
      ),
    consumeEmailOtpGrant: assembly.emailOtpRecoveryService.consumeEmailOtpGrant.bind(
      assembly.emailOtpRecoveryService,
    ),
    createEmailOtpChallenge: assembly.emailOtpChallengeService.createEmailOtpChallenge.bind(
      assembly.emailOtpChallengeService,
    ),
    createEmailOtpEnrollmentChallenge:
      assembly.emailOtpChallengeService.createEmailOtpEnrollmentChallenge.bind(
        assembly.emailOtpChallengeService,
      ),
    isEmailOtpStrongAuthRequired:
      assembly.emailOtpRecoveryService.isEmailOtpStrongAuthRequired.bind(
        assembly.emailOtpRecoveryService,
      ),
    markEmailOtpStrongAuthSatisfied:
      assembly.emailOtpRecoveryService.markEmailOtpStrongAuthSatisfied.bind(
        assembly.emailOtpRecoveryService,
      ),
    readActiveEmailOtpEnrollment:
      assembly.emailOtpRecoveryService.readActiveEmailOtpEnrollment.bind(
        assembly.emailOtpRecoveryService,
      ),
    readEmailOtpEnrollment: assembly.emailOtpRecoveryService.readEmailOtpEnrollment.bind(
      assembly.emailOtpRecoveryService,
    ),
    readEmailOtpOutboxEntry: assembly.emailOtpChallengeService.readEmailOtpOutboxEntry.bind(
      assembly.emailOtpChallengeService,
    ),
    removeEmailOtpServerSeal: assembly.emailOtpServerSeal.removeEmailOtpServerSeal.bind(
      assembly.emailOtpServerSeal,
    ),
    validateGoogleEmailOtpRegistrationCandidateWallet:
      assembly.googleEmailOtpSessions.validateRegistrationCandidateWallet.bind(
        assembly.googleEmailOtpSessions,
      ),
    verifyEmailOtpChallenge: assembly.emailOtpChallengeService.verifyEmailOtpChallenge.bind(
      assembly.emailOtpChallengeService,
    ),
    verifyEmailOtpWalletRecoveryChallenge:
      assembly.emailOtpChallengeService.verifyEmailOtpWalletRecoveryChallenge.bind(
        assembly.emailOtpChallengeService,
      ),
    verifyEmailOtpEnrollment: assembly.emailOtpChallengeService.verifyEmailOtpEnrollment.bind(
      assembly.emailOtpChallengeService,
    ),
    verifyGoogleLogin: assembly.oidcVerification.verifyGoogleLogin.bind(assembly.oidcVerification),
  };
}

function createD1WebAuthnRouteService(
  assembly: D1WebAuthnRouteServiceAssembly,
): RouterApiServiceBag['webAuthn'] {
  return {
    createWebAuthnLoginOptions: assembly.webAuthnAuthService.createWebAuthnLoginOptions.bind(
      assembly.webAuthnAuthService,
    ),
    createWebAuthnSyncAccountOptions:
      assembly.webAuthnAuthService.createWebAuthnSyncAccountOptions.bind(
        assembly.webAuthnAuthService,
      ),
    listWebAuthnAuthenticatorsForUser:
      assembly.webAuthnAuthService.listWebAuthnAuthenticatorsForUser.bind(
        assembly.webAuthnAuthService,
      ),
    verifyWebAuthnAuthenticationLite:
      assembly.webAuthnAuthService.verifyWebAuthnAuthenticationLite.bind(
        assembly.webAuthnAuthService,
      ),
    verifyWebAuthnLogin: assembly.webAuthnAuthService.verifyWebAuthnLogin.bind(
      assembly.webAuthnAuthService,
    ),
    verifyWebAuthnSyncAccount: assembly.webAuthnAuthService.verifyWebAuthnSyncAccount.bind(
      assembly.webAuthnAuthService,
    ),
  };
}

function createD1IdentityRouteService(
  assembly: D1IdentityRouteServiceAssembly,
): RouterApiServiceBag['identity'] {
  return {
    consumeGoogleEmailOtpRegistrationAttemptRateLimit:
      assembly.googleEmailOtpSessions.consumeRegistrationAttemptRateLimit.bind(
        assembly.googleEmailOtpSessions,
      ),
    getGoogleOidcPublicConfig: assembly.oidcVerification.getGoogleOidcPublicConfig.bind(
      assembly.oidcVerification,
    ),
    getGithubOAuthPublicConfig: assembly.oidcVerification.getGithubOAuthPublicConfig.bind(
      assembly.oidcVerification,
    ),
    linkIdentity: assembly.identityService.linkIdentity.bind(assembly.identityService),
    listIdentities: assembly.identityService.listIdentities.bind(assembly.identityService),
    resolveGoogleEmailOtpSession: assembly.googleEmailOtpSessions.resolve.bind(
      assembly.googleEmailOtpSessions,
    ),
    resolveOidcWalletId: assembly.identityService.resolveOidcWalletId.bind(
      assembly.identityService,
    ),
    unlinkIdentity: assembly.identityService.unlinkIdentity.bind(assembly.identityService),
    verifyGoogleLogin: assembly.oidcVerification.verifyGoogleLogin.bind(assembly.oidcVerification),
    verifyGithubOAuthCode: assembly.oidcVerification.verifyGithubOAuthCode.bind(
      assembly.oidcVerification,
    ),
  };
}

function createD1AuthorizationSessionRouteService(
  assembly: D1AuthorizationSessionRouteServiceAssembly,
): RouterApiServiceBag['authorizationSessions'] {
  const tenantId = parseTenantId(assembly.options.orgId);
  if (!tenantId.ok) {
    throw new Error(`orgId cannot identify an authorization tenant: ${tenantId.error.message}`);
  }
  return {
    tenantId: tenantId.value,
    issueReusableWalletSession: assembly.authorizationService.issueReusableWalletSession.bind(
      assembly.authorizationService,
    ),
    issueOpaqueWalletSessionToken: assembly.authorizationService.issueOpaqueWalletSessionToken.bind(
      assembly.authorizationService,
    ),
    resolveOpaqueWalletSessionToken:
      assembly.authorizationService.resolveOpaqueWalletSessionToken.bind(
        assembly.authorizationService,
      ),
    readReusableWalletSessionStatus:
      assembly.authorizationService.readReusableWalletSessionStatus.bind(
        assembly.authorizationService,
      ),
    readLinkedDeviceWalletSessionAuthorization:
      assembly.authorizationService.readLinkedDeviceWalletSessionAuthorization.bind(
        assembly.authorizationService,
      ),
    renewLinkedDeviceWalletSession:
      assembly.authorizationService.renewLinkedDeviceWalletSession.bind(
        assembly.authorizationService,
      ),
    mintHostedWalletSeamsSessionExchange:
      assembly.authorizationService.mintHostedWalletSeamsSessionExchange.bind(
        assembly.authorizationService,
      ),
    redeemHostedWalletSeamsSessionExchange:
      assembly.authorizationService.redeemHostedWalletSeamsSessionExchange.bind(
        assembly.authorizationService,
      ),
  };
}

function createD1AuthorizedOperationRouteService(
  assembly: D1AuthorizationSessionRouteServiceAssembly,
): RouterApiServiceBag['authorizedOperations'] {
  const tenantId = parseTenantId(assembly.options.orgId);
  if (!tenantId.ok) {
    throw new Error(`orgId cannot identify an authorization tenant: ${tenantId.error.message}`);
  }
  return {
    tenantId: tenantId.value,
    buildVerifiedOwnerProof: assembly.authorizationService.buildVerifiedOwnerProof.bind(
      assembly.authorizationService,
    ),
    recordVerifiedWalletOperationFactorEvidenceSet:
      assembly.authorizationService.recordVerifiedWalletOperationFactorEvidenceSet.bind(
        assembly.authorizationService,
      ),
    readAuthorizedOperationById: assembly.authorizationService.readAuthorizedOperationById.bind(
      assembly.authorizationService,
    ),
    readAuthorizedOperation: assembly.authorizationService.readAuthorizedOperation.bind(
      assembly.authorizationService,
    ),
    admitAuthorizedOperation: assembly.authorizationService.admitAuthorizedOperation.bind(
      assembly.authorizationService,
    ),
    completeAuthorizedOperation: assembly.authorizationService.completeAuthorizedOperation.bind(
      assembly.authorizationService,
    ),
  };
}

function createD1ThresholdRuntimeRouteService(
  assembly: D1ThresholdRuntimeRouteServiceAssembly,
): CloudflareD1RouterApiAuthService['thresholdRuntime'] {
  return {
    getRouterAbEcdsaPresignRuntime: () => assembly.options.routerAbEcdsaPresignRuntime || null,
  };
}

function createD1NearFundingRouteService(
  assembly: D1NearFundingRouteServiceAssembly,
): RouterApiServiceBag['nearFunding'] {
  return {
    fundImplicitNearAccount: fundImplicitNearAccountForOptions.bind(undefined, assembly.options),
    listNearPublicKeysForUser: assembly.nearPublicKeys.listForRelayUser.bind(
      assembly.nearPublicKeys,
    ),
  };
}

function createD1RouterAccountRouteService(
  assembly: D1RouterAccountRouteServiceAssembly,
): RouterApiServiceBag['router'] {
  const accountId = assembly.options.relayerAccount || DEFAULT_D1_THRESHOLD_RELAYER_ACCOUNT;
  const publicKey = assembly.options.relayerPublicKey || DEFAULT_D1_THRESHOLD_RELAYER_PUBLIC_KEY;
  return {
    getConfiguredRelayerAccount: () => accountId,
    getRelayerAccount: async () => ({ accountId, publicKey }),
  };
}

export function createCloudflareD1RouterApiAuthService(
  input: CloudflareD1RouterApiAuthServiceOptions,
): CloudflareD1RouterApiAuthService {
  const assembly = createCloudflareD1RouterApiAuthAssembly(input);
  return {
    walletRegistration: createD1WalletRegistrationRouteService(assembly),
    walletAuthMethods: createD1WalletAuthMethodRouteService(assembly),
    walletUnlock: createD1WalletUnlockRouteService(assembly),
    emailOtp: createD1EmailOtpRouteService(assembly),
    webAuthn: createD1WebAuthnRouteService(assembly),
    identity: createD1IdentityRouteService(assembly),
    authorizationSessions: createD1AuthorizationSessionRouteService(assembly),
    authorizedOperations: createD1AuthorizedOperationRouteService(assembly),
    thresholdRuntime: createD1ThresholdRuntimeRouteService(assembly),
    nearFunding: createD1NearFundingRouteService(assembly),
    router: createD1RouterAccountRouteService(assembly),
    passkeyCustody: createD1PasskeyCustodyRouteService({
      passkeyCustodyEnvelopes: assembly.passkeyCustodyEnvelopes,
      walletCustodyCommits: assembly.walletCustodyCommitStore,
      walletStore: assembly.walletStore,
      webAuthnStore: assembly.webAuthnStore,
      logger: normalizeLogger(),
    }),
    executeSignedDelegate: assembly.signedDelegateExecutor.execute.bind(
      assembly.signedDelegateExecutor,
    ),
    ...(assembly.deviceLinking === undefined ? {} : { deviceLinking: assembly.deviceLinking }),
    ...(assembly.deviceManagement === undefined
      ? {}
      : { deviceManagement: assembly.deviceManagement }),
    ...(assembly.linkedDeviceExecution === undefined
      ? {}
      : { linkedDeviceExecution: assembly.linkedDeviceExecution }),
    ...(assembly.linkedDeviceLocalPresence === undefined
      ? {}
      : { linkedDeviceLocalPresence: assembly.linkedDeviceLocalPresence }),
    ...(assembly.deviceLinkingGateway === undefined
      ? {}
      : { deviceLinkingGateway: assembly.deviceLinkingGateway }),
    ...(assembly.deviceLinkingOwnerAuthorization === undefined
      ? {}
      : { deviceLinkingOwnerAuthorization: assembly.deviceLinkingOwnerAuthorization }),
    ...(assembly.deviceLinkingLaneGateway === undefined
      ? {}
      : { deviceLinkingLaneGateway: assembly.deviceLinkingLaneGateway }),
  };
}
