import { parseRouterAbEcdsaRegistrationActivationReceiptV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseRegistrationEstablishedSessionProjectionV2,
  parseRegistrationEstablishedSessionResultV2,
} from '@shared/utils/registrationEstablishedSession';
import {
  parseDeviceId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  type WalletSessionClientCapabilityV1,
} from '@shared/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
} from '@shared/utils/domainIds';
import {
  computeWalletAuthMethodRevokeOperationFingerprintV1,
} from '@shared/utils/registrationIntent';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import type {
  WalletRegistrationActivateResponseV2,
  WalletRegistrationSessionCommitReceiptV2,
} from '../../../../core/threeRouteRegistrationContracts';
import type { WalletRegistrationFinalizeResponse } from '../../../../core/registrationContracts';
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
import { alphabetizeStringify, sha256BytesUtf8, sha256HexUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type {
  AccountCreationResult,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
} from '../../../../core/types';
import {
  parseWalletUnlockIssuanceRejectionCode,
  type WalletUnlockEmailOtpAuthorityResolution,
  type WalletUnlockPasskeyAuthorityResolution,
  type WalletUnlockPasskeySessionResolution,
  type RouterApiServiceBag,
} from '../../../framework/authServicePort';
import type {
  DirectV2IssueResult,
  IssuedWalletSessionAuthorizationV2,
} from '../../../../authorization/domain';
import { WALLET_UNLOCK_EXACT_RESPONSE_FAMILY_V1 } from '../../../../authorization/domain';
import { AuthorizationService } from '../../../../authorization/service';
import { capabilityPolicyPort } from '../../../../authorization/capabilityPolicy';
import { CloudflareD1AuthorizationStore } from '../authorization/d1AuthorizationStore';
import { parseTenantId } from '@shared/authorization/capabilityKinds';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../registration/d1RegistrationCeremonyStore';
import { isRecordValue, sha256BytesPortable, toRecordValue } from './d1RouterApiAuthBoundary';
import { CloudflareD1NearPublicKeyStore } from '../near/d1NearPublicKeyStore';
import { CloudflareD1WebAuthnStore } from '../webauthn/d1WebAuthnStore';
import { parseWebAuthnAuthenticationCredential } from '../../../auth/webAuthnCredentialCodecs';
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
  parseD1WalletRegistrationFinalizeReplayResponse,
  parseD1WalletRegistrationFinalizeTerminalResponse,
} from '../registration/d1RegistrationCeremonyRecords';
import { parseWalletRegistrationSessionCommitReceiptV2 } from '../registration/walletRegistrationSessionCommitReceipt';
import { CloudflareD1WalletRegistrationCommitStore } from '../registration/d1WalletRegistrationCommitStore';
import { CloudflareD1WalletCustodyCommitStore } from '../passkeyCustody/d1WalletCustodyCommitStore';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import { createD1PasskeyCustodyRouteService } from '../passkeyCustody/d1PasskeyCustodyRouteService';
import { CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore } from '../passkeyCustody/d1WalletRecoveryGoogleEmailOtpAttemptStore';
import { CloudflareD1WalletRecoveryGoogleEmailOtpService } from '../passkeyCustody/d1WalletRecoveryGoogleEmailOtpService';
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
  parseRouterAbEd25519YaoRegistrationSideEffectRecordV2WithLegacy,
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV2,
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
import type { DeviceLinkingRouteServiceV1 } from '../../../transport/fetch/routes/deviceLinking';
import { D1LinkedDeviceEmailOtpGrantStoreV1 } from '../deviceLinking/d1LinkedDeviceEmailOtpGrantStore';
import { D1LinkedDeviceAuthorityInstallServiceV1 } from '../deviceLinking/d1LinkedDeviceAuthorityInstallService';
import { createD1LinkedDeviceSessionServiceV1 } from '../deviceLinking/d1LinkedDeviceSessionService';
import { D1LinkedDeviceSessionStoreV1 } from '../deviceLinking/d1LinkedDeviceSessionStore';
import { createD1LinkedDeviceManagementServiceV1 } from '../deviceLinking/d1LinkedDeviceManagementService';
import { D1WalletAuthorityStore } from '../wallet/d1WalletAuthorityStore';
import { verifyD1LinkedDeviceFreshRevokeProofV1 } from '../wallet/d1WalletAuthMethodBoundary';
import { createD1LinkedDeviceVerifiedLinkSourceReaderV1 } from '../deviceLinking/d1LinkedDeviceVerifiedLinkSourceReader';
import { LinkedDeviceWebAuthnRegistrationVerifierV1 } from '../deviceLinking/d1LinkedDeviceTargetCredentialProvider';
import {
  createCloudflareOrdinaryInactiveSignerMaterialActivationPortV1,
  createCloudflareOrdinaryInactiveSignerMaterialDeactivationPortV1,
  createCloudflareOrdinaryInactiveSignerMaterialReservationServiceV1,
} from '../../signingLanes/cloudflareOrdinaryInactiveSignerMaterialReservation';
import {
  D1LinkedDeviceEmailOtpTargetFactorV1,
  linkedDeviceEmailOtpGrantRegistrationPortV1,
} from '../deviceLinking/d1LinkedDeviceEmailOtpTargetFactor';
import { createDeviceLinkingOwnerRequestAuthenticatorV1 } from '../../../transport/fetch/routes/deviceLinkingOwnerAuthorization';
import {
  createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
  createD1LinkedDeviceOwnerAuthorizationProviderV1,
} from '../deviceLinking/d1LinkedDeviceOwnerAuthorizationProvider';

export type {
  CloudflareD1EmailOtpDeliveryProvider,
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
  CloudflareD1EmailOtpServerSealConfig,
  CloudflareD1LinkedDeviceAuthorityInstallationOptionsV1,
  CloudflareD1LinkedDeviceCompositionOptionsV1,
  CloudflareD1LinkedDeviceManagementOptionsV1,
  CloudflareD1LinkedDeviceSessionOptionsV1,
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

type LinkedDeviceEd25519AuthorityReader = Pick<
  D1LinkedDeviceAuthorityInstallServiceV1,
  | 'readInstalledEd25519AuthorityByIdentityV1'
  | 'readInstalledEd25519AuthorityByMaterialActivationV1'
>;

type LinkedDeviceEd25519AuthorityReaderSlot = {
  current: LinkedDeviceEd25519AuthorityReader | null;
};

function linkedDeviceEd25519AuthorityReaderFromSlot(
  slot: LinkedDeviceEd25519AuthorityReaderSlot,
): LinkedDeviceEd25519AuthorityReader | null {
  return slot.current;
}

type CloudflareD1RouterApiAuthAssembly = {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  readonly emailOtpServerSeal: CloudflareD1EmailOtpServerSealRuntime;
  readonly emailOtpChallengeService: CloudflareD1EmailOtpChallengeService;
  readonly emailOtpRecoveryService: CloudflareD1EmailOtpRecoveryService;
  readonly emailOtpRegistrationEnrollmentFinalizer: Pick<
    CloudflareD1EmailOtpRegistrationEnrollmentFinalizer,
    'prepareLinkedDeviceEnrollment'
  >;
  readonly walletRecoveryGoogleEmailOtp: CloudflareD1WalletRecoveryGoogleEmailOtpService;
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
  readonly walletAuthorityStore: D1WalletAuthorityStore;
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
  readonly deviceLinkingOwnerAuthorization?: RouterApiServiceBag['deviceLinkingOwnerAuthorization'];
  readonly linkedDeviceEd25519AuthorityReader?: LinkedDeviceEd25519AuthorityReader;
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
  | 'authorizationService'
  | 'emailOtpRecoveryService'
  | 'options'
  | 'walletAuthMethods'
  | 'webAuthnAuthService'
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
  'authorizationService' | 'options' | 'walletAuthMethodStore' | 'walletAuthorityStore'
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
  | 'deviceLinkingOwnerAuthorization'
  | 'linkedDeviceEd25519AuthorityReader'
>;

function createD1LinkedDeviceComposition(input: {
  readonly options: NormalizedCloudflareD1RouterApiAuthServiceOptions;
  readonly authorizationSessions: RouterApiServiceBag['authorizationSessions'];
  readonly authorizationService: AuthorizationService;
  readonly authorizationStore: Pick<
    CloudflareD1AuthorizationStore,
    | 'prepareWalletSessionAuthorizationV2Statements'
    | 'prepareRevokeReusableWalletSessionsForAuthority'
    | 'readOpaqueWalletSessionTokenByIdentity'
    | 'readActiveWalletSessionAuthorizationV2ByIdentity'
  >;
  readonly walletRegistration: Pick<
    RouterApiServiceBag['walletRegistration'],
    'resolveActiveOwnerWalletExecutionLane'
  >;
  readonly walletAuthMethodStore: D1WalletAuthMethodStore;
  readonly walletStore: D1WalletStore;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly webAuthnAuthService: CloudflareD1WebAuthnAuthService;
  /**
   * Refactor 103 Phase 6: the R100 Email OTP pieces the linked-device Email
   * OTP target factor composes. Left absent, `email_otp` linking fails closed
   * at approval and the challenge routes answer 501.
   */
  readonly emailOtpLinkedDevice?: {
    readonly issuer: Pick<CloudflareD1EmailOtpChallengeIssuer, 'create'>;
    readonly verifier: Pick<
      CloudflareD1EmailOtpChallengeVerifier,
      'verifyExisting' | 'verifyRegistration'
    >;
    readonly enrollments: Pick<CloudflareD1EmailOtpEnrollmentStore, 'readEnrollment'>;
    readonly walletAuthMethodStore: {
      listForWalletV2(input: { readonly walletId: string }): Promise<WalletAuthMethodRecordV2[]>;
    };
    readonly serverSeal: Pick<CloudflareD1EmailOtpServerSealRuntime, 'removeEmailOtpServerSeal'>;
    readonly enrollmentFinalizer: Pick<
      CloudflareD1EmailOtpRegistrationEnrollmentFinalizer,
      'prepareLinkedDeviceEnrollment'
    >;
  };
}): D1LinkedDeviceCompositionAssembly {
  const config = input.options.linkedDevice;
  if (!config) return {};
  const sessionConfig = 'session' in config ? config.session : undefined;
  const managementConfig = 'management' in config ? config.management : undefined;
  if (!sessionConfig && !managementConfig) return {};

  const scope = {
    namespace: input.options.namespace,
    orgId: input.options.orgId,
    projectId: input.options.projectId,
    envId: input.options.envId,
  };
  let deviceLinking: RouterApiServiceBag['deviceLinking'];
  let ownerAuthorizationRoute: RouterApiServiceBag['deviceLinkingOwnerAuthorization'];
  let linkedDeviceEd25519AuthorityReader: LinkedDeviceEd25519AuthorityReader | undefined;
  const nowV1 = sessionConfig?.nowV1 ?? managementConfig?.nowV1 ?? Date.now;
  const ownerRequestAuthenticator = createDeviceLinkingOwnerRequestAuthenticatorV1({
    authorizationSessions: input.authorizationSessions,
    nowV1,
  });
  const tenantId = parseTenantId(input.options.orgId);
  if (!tenantId.ok)
    throw new Error(`orgId cannot identify an authorization tenant: ${tenantId.error.message}`);
  const authorityStore = new D1WalletAuthorityStore({
    database: input.options.database,
    scope,
  });
  let deactivationEndpoint;
  if (sessionConfig) {
    deactivationEndpoint = sessionConfig.authorityInstallation.deactivationEndpoint;
  } else if (managementConfig) {
    deactivationEndpoint = managementConfig.deactivationEndpoint;
  } else {
    return {};
  }
  const deviceManagementService = createD1LinkedDeviceManagementServiceV1({
    scope,
    tenantId: tenantId.value,
    authorityStore,
    authMethodStore: input.walletAuthMethodStore,
    authorizationService: input.authorizationService,
    walletSessionAuthorizations: input.authorizationStore,
    webAuthnStore: input.webAuthnStore,
    materialDeactivation: createCloudflareOrdinaryInactiveSignerMaterialDeactivationPortV1({
      endpoint: deactivationEndpoint,
    }),
  });
  const deviceManagement: RouterApiServiceBag['deviceManagement'] = {
    management: deviceManagementService,
    nowV1,
    authenticateOwnerRequestV1: ownerRequestAuthenticator,
    verifyFreshRevokeProofV1: async (proofInput) => {
      const expectedOrigin = String(proofInput.request.headers.get('origin') || '').trim();
      if (!expectedOrigin) {
        return {
          kind: 'denied' as const,
          code: 'invalid' as const,
          message: 'Fresh revocation proof requires an Origin header',
        };
      }
      return await verifyD1LinkedDeviceFreshRevokeProofV1({
        walletId: proofInput.walletId,
        orgId: String(input.options.orgId),
        targetWalletAuthMethodId: proofInput.targetWalletAuthMethodId,
        proof: proofInput.proof,
        expectedOrigin,
        verifiedAtMs: proofInput.requestedAtMs,
        operationFingerprintDigest: await computeWalletAuthMethodRevokeOperationFingerprintV1({
          walletId: proofInput.walletId,
          targetWalletAuthMethodId: proofInput.targetWalletAuthMethodId,
          requestedAtMs: proofInput.requestedAtMs,
        }),
        walletAuthMethodStore: input.walletAuthMethodStore,
        verifyWebAuthnAuthenticationLite: async (verifyInput) => {
          const credential = parseWebAuthnAuthenticationCredential(
            verifyInput.webauthn_authentication,
          );
          if (!credential) {
            return {
              success: false,
              verified: false,
              code: 'invalid_body',
              message: 'Invalid WebAuthn authentication credential',
            };
          }
          return await input.webAuthnAuthService.verifyWebAuthnAuthenticationLite({
            ...verifyInput,
            webauthn_authentication: credential,
          });
        },
        ...(input.emailOtpLinkedDevice === undefined
          ? {}
          : {
              verifyEmailOtpExisting: input.emailOtpLinkedDevice.verifier.verifyExisting.bind(
                input.emailOtpLinkedDevice.verifier,
              ),
              readEmailOtpEnrollment: input.emailOtpLinkedDevice.enrollments.readEnrollment.bind(
                input.emailOtpLinkedDevice.enrollments,
              ),
            }),
      });
    },
  };
  if (!sessionConfig) {
    return { deviceManagement };
  }
  if (sessionConfig) {
    let emailOtpTargetFactor: D1LinkedDeviceEmailOtpTargetFactorV1 | undefined;
    if (input.emailOtpLinkedDevice) {
      const linkedEmailOtpGrants = new D1LinkedDeviceEmailOtpGrantStoreV1({
        database: input.options.database,
        scope,
      });
      emailOtpTargetFactor = new D1LinkedDeviceEmailOtpTargetFactorV1({
        issuer: input.emailOtpLinkedDevice.issuer,
        verifier: input.emailOtpLinkedDevice.verifier,
        enrollments: input.emailOtpLinkedDevice.enrollments,
        orgId: input.options.orgId,
        walletAuthMethods: input.emailOtpLinkedDevice.walletAuthMethodStore,
        walletAuthorities: authorityStore,
        serverSeal: input.emailOtpLinkedDevice.serverSeal,
        grants: linkedEmailOtpGrants,
      });
    }
    const sessionStore = new D1LinkedDeviceSessionStoreV1({
      database: input.options.database,
      scope,
      now: nowV1,
    });
    const verifiedLinkSourceReader = createD1LinkedDeviceVerifiedLinkSourceReaderV1({
      authorizationService: input.authorizationService,
      authorityStore,
      authMethodStore: input.walletAuthMethodStore,
      walletStore: input.walletStore,
      tenantId: tenantId.value,
    });
    const ownerAuthorizationProvider = createD1LinkedDeviceOwnerAuthorizationProviderV1({
      walletRegistration: input.walletRegistration,
      metadata: createD1LinkedDeviceOwnerAuthorizationMetadataSourceV1({
        sessionStore,
        readVerifiedSourceV1: verifiedLinkSourceReader.readVerifiedSourceV1,
        readOwnerSourceChildV1: sessionConfig.readOwnerSourceChildV1,
        nowV1,
      }),
      targetPlanner: { targetPasskeyRpId: sessionConfig.targetPasskeyRpId },
      nowV1,
    });
    ownerAuthorizationRoute = ownerAuthorizationProvider.ownerAuthorizationRoute;
    const sessionComposition = createD1LinkedDeviceSessionServiceV1({
      sessionStore,
      ownerAuthorization: ownerAuthorizationProvider.ownerAuthorization,
    });
    const verifiedLinkBuilder = {
      source: verifiedLinkSourceReader,
    };
    const authorityInstall = new D1LinkedDeviceAuthorityInstallServiceV1({
      database: input.options.database,
      scope,
      authorityStore,
      authMethodStore: input.walletAuthMethodStore,
      listWalletEd25519Signers: (walletId) =>
        input.walletStore.listEd25519SignersForWallet({ walletId }),
      sessionStore: sessionComposition.sessionStore,
      sessionService: sessionComposition.sessionService,
      reservationService: createCloudflareOrdinaryInactiveSignerMaterialReservationServiceV1({
        endpoint: sessionConfig.authorityInstallation.reservationEndpoint,
      }),
      materialActivation: createCloudflareOrdinaryInactiveSignerMaterialActivationPortV1({
        endpoint: sessionConfig.authorityInstallation.activationEndpoint,
      }),
      authorizationService: input.authorizationService,
      authorizationStore: input.authorizationStore,
      ...(input.emailOtpLinkedDevice === undefined
        ? {}
        : { emailOtpEnrollmentFinalizer: input.emailOtpLinkedDevice.enrollmentFinalizer }),
      tenantId: tenantId.value,
      nowV1,
    });
    linkedDeviceEd25519AuthorityReader = authorityInstall;
    const installationReceipt: NonNullable<DeviceLinkingRouteServiceV1['installationReceipt']> = {
      commitPendingAuthorityV1: async ({
        input: verifiedLinkInput,
        nowMs,
        ed25519ExportRootPackage,
      }) =>
        await authorityInstall.commitPendingAuthorityV1({
          ...verifiedLinkInput,
          nowMs,
          ed25519ExportRootPackage,
        }),
      readCommittedAuthorityPackagesV1:
        authorityInstall.readCommittedAuthorityPackagesV1.bind(authorityInstall),
      activateInstalledAuthorityV1: async ({ receipt, requestedAtMs }) =>
        await authorityInstall.activateInstalledAuthorityV1({ receipt, nowMs: requestedAtMs }),
      acknowledgeLocalAuthorityActivationV1:
        authorityInstall.acknowledgeLocalAuthorityActivationV1.bind(authorityInstall),
    };
    deviceLinking = createD1LinkedDeviceRouteServiceV1({
      database: input.options.database,
      scope,
      ownerAuthorization: ownerAuthorizationProvider.ownerAuthorization,
      ...(emailOtpTargetFactor === undefined
        ? {}
        : {
            emailOtpTargetFactor,
          }),
      authenticateOwnerRequestV1: ownerRequestAuthenticator,
      targetCredential: sessionConfig.targetCredential({
        verifiedLinkBuilder,
        targetCredentialVerification: new LinkedDeviceWebAuthnRegistrationVerifierV1(
          ownerAuthorizationProvider.targetPlanner.targetPasskeyRpId,
        ),
        targetPlanner: ownerAuthorizationProvider.targetPlanner,
        resolveOwnerSourceChildV1:
          ownerAuthorizationProvider.ownerSourceResolver.resolveOwnerSourceChildV1,
        ...(emailOtpTargetFactor === undefined
          ? {}
          : { emailOtpGrants: linkedDeviceEmailOtpGrantRegistrationPortV1(emailOtpTargetFactor) }),
      }),
      installationReceipt,
      ...(sessionConfig.sourceContributionRouter === undefined
        ? {}
        : { sourceContributionRouter: sessionConfig.sourceContributionRouter }),
      nowV1,
    });
  }

  return {
    ...(deviceLinking === undefined ? {} : { deviceLinking }),
    ...(deviceManagement === undefined ? {} : { deviceManagement }),
    ...(ownerAuthorizationRoute === undefined
      ? {}
      : { deviceLinkingOwnerAuthorization: ownerAuthorizationRoute }),
    ...(linkedDeviceEd25519AuthorityReader === undefined
      ? {}
      : { linkedDeviceEd25519AuthorityReader }),
  };
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
  if (!isRecordValue(raw) || raw.kind !== 'd1_wallet_registration_operation_prepared_v1') {
    return null;
  }
  const record = raw;
  const keys = ['kind', 'walletAuthorityId', 'deviceId', 'walletAuthMethodId'];
  const recordKeys = Object.keys(record);
  if (recordKeys.length !== keys.length || !hasOnlyKeys(record, keys)) {
    return null;
  }
  const walletAuthorityId = parseWalletAuthorityId(record.walletAuthorityId);
  const deviceId = parseDeviceId(record.deviceId);
  const walletAuthMethodId = parseWalletAuthMethodId(record.walletAuthMethodId);
  if (!walletAuthorityId.ok || !deviceId.ok || !walletAuthMethodId.ok) return null;
  return {
    kind: 'd1_wallet_registration_operation_prepared_v1',
    walletAuthorityId: walletAuthorityId.value,
    deviceId: deviceId.value,
    walletAuthMethodId: walletAuthMethodId.value,
  };
}

function hasOnlyKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(record).every((key) => allowed.has(key));
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(record).length === keys.length && hasOnlyKeys(record, keys);
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
  const parsedRegistrationEstablishedSession = parseRegistrationEstablishedSessionResultV2(
    raw.registrationEstablishedSession,
  );
  if (
    !parsedRegistrationEstablishedSession ||
    parsedRegistrationEstablishedSession.session.walletId !== commit.walletId
  ) {
    return null;
  }
  const registrationEstablishedSession = parsedRegistrationEstablishedSession;
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

function parseWalletRegistrationSessionCommitReceipt(
  raw: unknown,
): WalletRegistrationSessionCommitReceiptV2 | null {
  const record = toRecordValue(raw);
  if (!record) return null;
  return parseWalletRegistrationSessionCommitReceiptV2(record, (committed) =>
    parseWalletRegistrationSessionCommitReceiptCommitted(committed, record),
  );
}

type WalletRegistrationEcdsaSessionCommitReceipt = Extract<
  WalletRegistrationSessionCommitReceiptV2,
  { readonly committed: { readonly kind: 'ecdsa_ready' } }
>['committed'];

type WalletRegistrationNearSessionCommitReceipt = Extract<
  WalletRegistrationSessionCommitReceiptV2,
  { readonly committed: { readonly kind: 'near_ready' } }
>['committed'];

function parseWalletRegistrationSessionCommitReceiptCommitted(
  raw: unknown,
  receipt: Record<string, unknown>,
): WalletRegistrationSessionCommitReceiptV2['committed'] | null {
  const record = toRecordValue(raw);
  if (!record || typeof record.kind !== 'string') return null;
  if (record.kind === 'ecdsa_ready') {
    if (
      !hasExactKeys(record, ['kind', 'ecdsa', 'session']) &&
      !hasExactKeys(record, ['kind', 'ecdsa', 'session', 'nearProvisioning'])
    ) {
      return null;
    }
    const ecdsa = parseWalletRegistrationSessionCommitEcdsa(record.ecdsa, receipt);
    const session = parseRegistrationEstablishedSessionProjectionV2(record.session);
    if (!ecdsa || !session || session.tokens.kind !== 'evm_family_ecdsa') return null;
    const nearProvisioning = parseNearPendingProjection(record.nearProvisioning);
    if (record.nearProvisioning !== undefined && !nearProvisioning) return null;
    return {
      kind: 'ecdsa_ready',
      ecdsa,
      session,
      ...(nearProvisioning ? { nearProvisioning } : {}),
    };
  }
  if (record.kind !== 'near_ready') return null;
  if (
    !hasExactKeys(record, [
      'kind',
      'authorityScope',
      'accountProvisioning',
      'resolvedAccount',
      'ed25519',
      'session',
      'nearProvisioning',
    ])
  ) {
    return null;
  }
  const near = parseWalletRegistrationSessionCommitNear(record, receipt);
  const session = parseRegistrationEstablishedSessionProjectionV2(record.session);
  if (!near || !session || session.tokens.kind !== 'near_ed25519') return null;
  return {
    kind: 'near_ready',
    authorityScope: near.authorityScope,
    accountProvisioning: near.accountProvisioning,
    resolvedAccount: near.resolvedAccount,
    ed25519: near.ed25519,
    session,
    nearProvisioning: { status: 'near_ready' },
  };
}

function parseWalletRegistrationSessionCommitEcdsa(
  raw: unknown,
  receipt: Record<string, unknown>,
): WalletRegistrationEcdsaSessionCommitReceipt['ecdsa'] | null {
  const record = toRecordValue(raw);
  if (!record || !hasExactKeys(record, ['walletKeys', 'activation', 'bootstrap'])) {
    return null;
  }
  const response = parseD1WalletRegistrationFinalizeReplayResponse({
    ok: true,
    kind: 'evm_family_ecdsa',
    walletId: receipt.walletId,
    authority: receipt.authority,
    foundingAuthority: receipt.foundingAuthority,
    foundingAuthMethod: receipt.foundingAuthMethod,
    authMethod: receipt.authMethod,
    ...(isRecordValue(receipt.authority) &&
    isRecordValue(receipt.authority.verifier) &&
    receipt.authority.verifier.kind === 'webauthn'
      ? { rpId: receipt.authority.verifier.rpId }
      : {}),
    custodyKeyManifestDigestB64u: receipt.custodyKeyManifestDigestB64u,
    ecdsa: { walletKeys: record.walletKeys },
  });
  if (!response || !response.ok || response.kind !== 'evm_family_ecdsa') {
    return null;
  }
  let activation: ReturnType<typeof parseRouterAbEcdsaRegistrationActivationReceiptV1>;
  try {
    activation = parseRouterAbEcdsaRegistrationActivationReceiptV1(record.activation);
  } catch {
    return null;
  }
  const bootstrap = parseD1EcdsaDerivationServerBootstrapResponse(record.bootstrap);
  if (!bootstrap) return null;
  return {
    walletKeys: response.ecdsa.walletKeys,
    activation,
    bootstrap,
  };
}

function parseWalletRegistrationSessionCommitNear(
  record: Record<string, unknown>,
  receipt: Record<string, unknown>,
): {
  readonly authorityScope: WalletRegistrationNearSessionCommitReceipt['authorityScope'];
  readonly accountProvisioning: WalletRegistrationNearSessionCommitReceipt['accountProvisioning'];
  readonly resolvedAccount: WalletRegistrationNearSessionCommitReceipt['resolvedAccount'];
  readonly ed25519: WalletRegistrationNearSessionCommitReceipt['ed25519'];
} | null {
  const response = parseD1WalletRegistrationFinalizeReplayResponse({
    ok: true,
    kind: 'near_ed25519',
    walletId: receipt.walletId,
    authority: receipt.authority,
    foundingAuthority: receipt.foundingAuthority,
    foundingAuthMethod: receipt.foundingAuthMethod,
    authMethod: receipt.authMethod,
    ...(isRecordValue(receipt.authority) &&
    isRecordValue(receipt.authority.verifier) &&
    receipt.authority.verifier.kind === 'webauthn'
      ? { rpId: receipt.authority.verifier.rpId }
      : {}),
    custodyKeyManifestDigestB64u: receipt.custodyKeyManifestDigestB64u,
    authorityScope: record.authorityScope,
    accountProvisioning: record.accountProvisioning,
    resolvedAccount: record.resolvedAccount,
    ed25519: record.ed25519,
  });
  if (!response || !response.ok || response.kind !== 'near_ed25519') return null;
  return {
    authorityScope: response.authorityScope,
    accountProvisioning: response.accountProvisioning,
    resolvedAccount: response.resolvedAccount,
    ed25519: response.ed25519,
  };
}

function parseNearPendingProjection(raw: unknown): { readonly status: 'near_pending' } | null {
  const record = toRecordValue(raw);
  return record && hasExactKeys(record, ['status']) && record.status === 'near_pending'
    ? { status: 'near_pending' }
    : null;
}

function parseWalletRegistrationActivateSideEffectRecord(
  raw: unknown,
): D1WalletRegistrationActivateSideEffectRecord | null {
  const record = parseRouterAbEd25519YaoRegistrationSideEffectRecordV2WithLegacy<
    WalletRegistrationActivateResponseV2,
    WalletRegistrationSessionCommitReceiptV2,
    D1WalletRegistrationOperationPreparedV1
  >(raw, {
    operation: 'registration_activate',
    parsePrepared: parseWalletRegistrationOperationPrepared,
    parseReceipt: parseWalletRegistrationSessionCommitReceipt,
    parseLegacyResponse: parseD1WalletRegistrationActivateTerminalResponse,
  });
  if (record === null || !registrationReceiptMatchesJournal(record)) return null;
  return record;
}

/**
 * Deferred NEAR provisioning's own operation row. Same record shape as the
 * finalize journal it replaces for this route, tagged with its own operation
 * so a provisioning row can never be read as an activate or finalize row.
 */
function parseWalletRegistrationNearProvisioningSideEffectRecord(
  raw: unknown,
): D1WalletRegistrationNearProvisioningSideEffectRecord | null {
  const record = parseRouterAbEd25519YaoRegistrationSideEffectRecordV2WithLegacy<
    WalletRegistrationFinalizeResponse,
    WalletRegistrationSessionCommitReceiptV2,
    D1WalletRegistrationOperationPreparedV1
  >(raw, {
    operation: 'near_provisioning',
    parsePrepared: parseWalletRegistrationOperationPrepared,
    parseReceipt: parseWalletRegistrationSessionCommitReceipt,
    parseLegacyResponse: parseD1WalletRegistrationFinalizeTerminalResponse,
  });
  if (record === null || !registrationReceiptMatchesJournal(record)) return null;
  return record;
}

function registrationReceiptMatchesJournal<T>(
  record: RouterAbEd25519YaoRegistrationSideEffectRecordV2<
    WalletRegistrationSessionCommitReceiptV2,
    D1WalletRegistrationOperationPreparedV1,
    T
  >,
): boolean {
  if (record.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v2') return true;
  const receipt = record.receipt;
  if (
    receipt.operation !== record.operation ||
    receipt.operationFingerprint !== record.requestFingerprint
  ) {
    return false;
  }
  if (receipt.committed.kind === 'error') return true;
  if (!('walletAuthMethodId' in receipt)) return false;
  if (receipt.walletAuthMethodId !== record.prepared.walletAuthMethodId) return false;
  if (receipt.committed.kind === 'near_pending') return true;
  return (
    'foundingAuthority' in receipt &&
    receipt.foundingAuthority.authorityId === record.prepared.walletAuthorityId
  );
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
  const walletAuthorityStore = new D1WalletAuthorityStore({
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
    emailOtpEnrollmentChallengeIssuer: (challengeInput) =>
      emailOtpChallengeService.createEmailOtpEnrollmentChallenge(challengeInput),
    emailOtpSourceChallengeIssuer: (challengeInput) =>
      emailOtpChallengeService.createEmailOtpChallenge(challengeInput),
    emailOtpEnrollmentFinalizer: emailOtpRegistrationEnrollmentFinalizer,
    getRegistrationCeremonyIntentStore,
    getWalletAuthMethodStore,
    googleEmailOtpRegistrationAttempts,
    prepareOwnerWalletSessionRevocation: (sessionInput) =>
      authorizationStore.prepareRevokeReusableWalletSessionsForAuthMethod({
        tenantId: authorizationTenantId.value,
        walletId: sessionInput.walletId,
        walletAuthMethodId: sessionInput.walletAuthMethodId,
        nowMs: sessionInput.requestedAtMs,
      }),
    passkeyCustodyEnvelopes,
    sha256Bytes: sha256BytesPortable,
    webAuthnStore,
    listWalletEd25519Signers: (walletId) => walletStore.listEd25519SignersForWallet({ walletId }),
    walletAuthorityStore,
    orgId: options.orgId,
    verifyWebAuthnAuthenticationLite: async (verifyInput) => {
      const credential = parseWebAuthnAuthenticationCredential(verifyInput.webauthn_authentication);
      if (!credential) {
        return {
          success: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid WebAuthn authentication credential',
        };
      }
      return await webAuthnAuthService.verifyWebAuthnAuthenticationLite({
        ...verifyInput,
        webauthn_authentication: credential,
      });
    },
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
  const linkedDeviceEd25519AuthorityReaderSlot: LinkedDeviceEd25519AuthorityReaderSlot = {
    current: null,
  };
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
    getLinkedDeviceEd25519AuthorityReader: linkedDeviceEd25519AuthorityReaderFromSlot.bind(
      undefined,
      linkedDeviceEd25519AuthorityReaderSlot,
    ),
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
  const walletRecoveryGoogleEmailOtpAttempts =
    new CloudflareD1WalletRecoveryGoogleEmailOtpAttemptStore({
      database: options.database,
      scope: {
        namespace: options.namespace,
        orgId: options.orgId,
        projectId: options.projectId,
        envId: options.envId,
      },
    });
  const walletRecoveryGoogleEmailOtp = new CloudflareD1WalletRecoveryGoogleEmailOtpService({
    attempts: walletRecoveryGoogleEmailOtpAttempts,
    google: {
      verifyGoogleLoginForRecovery:
        oidcVerification.verifyGoogleLoginForRecovery.bind(oidcVerification),
    },
    issuer: emailOtpChallengeIssuer,
    verifier: emailOtpChallengeVerifier,
    enrollments: emailOtpEnrollments,
    serverSeal: emailOtpServerSeal,
    orgId: options.orgId,
  });
  // Composed after the R100 Email OTP pieces so the linked-device Email OTP
  // target factor reuses this deployment's exact issuer, verifier, enrollment
  // store, and server-seal runtime — never a second OTP implementation.
  const linkedDeviceComposition = createD1LinkedDeviceComposition({
    emailOtpLinkedDevice: {
      issuer: emailOtpChallengeIssuer,
      verifier: emailOtpChallengeVerifier,
      enrollments: emailOtpEnrollments,
      walletAuthMethodStore,
      serverSeal: emailOtpServerSeal,
      enrollmentFinalizer: emailOtpRegistrationEnrollmentFinalizer,
    },
    options,
    authorizationService,
    authorizationStore,
    walletRegistration: createD1WalletRegistrationRouteService({
      emailOtpRecoveryService,
      registrationIntents,
      walletAuthMethodStore,
      walletRegistrations,
      walletStore,
    }),
    walletAuthMethodStore,
    walletStore,
    webAuthnStore,
    webAuthnAuthService,
    authorizationSessions: createD1AuthorizationSessionRouteService({
      authorizationService,
      options,
      walletAuthMethodStore,
      walletAuthorityStore,
    }),
  });
  linkedDeviceEd25519AuthorityReaderSlot.current =
    linkedDeviceComposition.linkedDeviceEd25519AuthorityReader ?? null;

  return {
    options,
    emailOtpServerSeal,
    emailOtpChallengeService,
    emailOtpRecoveryService,
    emailOtpRegistrationEnrollmentFinalizer,
    walletRecoveryGoogleEmailOtp,
    identityService,
    oidcVerification,
    authorizationService,
    googleEmailOtpSessions,
    nearPublicKeys,
    webAuthnAuthService,
    walletAuthMethods,
    walletRegistrations,
    walletAuthMethodStore,
    walletAuthorityStore,
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
    return await this.walletAuthMethodStore.listForWalletV2({ walletId: input.walletId });
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
    resolveActiveWalletSessionAuthority:
      assembly.walletAuthMethods.resolveActiveWalletSessionAuthority.bind(
        assembly.walletAuthMethods,
      ),
    verifyWalletAuthMethodRevokeProof:
      assembly.walletAuthMethods.verifyWalletAuthMethodRevokeProof.bind(assembly.walletAuthMethods),
    verifyActivePasskeyAuthority: assembly.walletAuthMethods.verifyActivePasskeyAuthority.bind(
      assembly.walletAuthMethods,
    ),
    resolveActivePasskeyAuthorityForVerifiedCredential:
      assembly.walletAuthMethods.resolveActivePasskeyAuthorityForVerifiedCredential.bind(
        assembly.walletAuthMethods,
      ),
    verifyActiveEmailOtpAuthority: assembly.walletAuthMethods.verifyActiveEmailOtpAuthority.bind(
      assembly.walletAuthMethods,
    ),
    resolveActiveEmailOtpAuthorityForVerifiedSubject:
      assembly.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject.bind(
        assembly.walletAuthMethods,
      ),
    resolveActiveEmailOtpAuthorityForVerifiedMethod:
      assembly.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedMethod.bind(
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
    createAddAuthMethodEmailOtpChallenge:
      assembly.walletAuthMethods.createAddAuthMethodEmailOtpChallenge.bind(
        assembly.walletAuthMethods,
      ),
    verifyAddAuthMethodEmailOtpSourceProof:
      assembly.walletAuthMethods.verifyAddAuthMethodEmailOtpSourceProof.bind(
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

const LINKED_DEVICE_WALLET_SESSION_TTL_MS = 15 * 60 * 1000;
const LINKED_DEVICE_WALLET_SESSION_REMAINING_USES = 100;

type ActiveWalletUnlockAuthorityResolution =
  | Extract<WalletUnlockPasskeyAuthorityResolution, { readonly kind: 'active_authority' }>
  | Extract<WalletUnlockEmailOtpAuthorityResolution, { readonly kind: 'active_authority' }>;

async function resolveEmailOtpAuthorityForUnlock(input: {
  readonly walletAuthMethods: Pick<
    CloudflareD1WalletAuthMethodService,
    'resolveActiveEmailOtpAuthorityForUnlock'
  >;
  readonly emailOtpRecoveryService: Pick<
    CloudflareD1EmailOtpRecoveryService,
    'readEmailOtpEnrollment'
  >;
  readonly request: Parameters<
    RouterApiServiceBag['walletUnlock']['resolveEmailOtpAuthorityForUnlock']
  >[0];
}): Promise<WalletUnlockEmailOtpAuthorityResolution> {
  try {
    const enrollment = await input.emailOtpRecoveryService.readEmailOtpEnrollment({
      walletId: input.request.walletId,
      orgId: input.request.orgId,
    });
    if (!enrollment.ok) {
      return {
        kind: 'rejected',
        code: parseWalletUnlockIssuanceRejectionCode(enrollment.code),
        message: enrollment.message,
      };
    }
    if (enrollment.enrollment.providerUserId !== input.request.providerUserId) {
      return {
        kind: 'rejected',
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not match the verified provider identity',
      };
    }
    const emailHashHex = await sha256HexUtf8(enrollment.enrollment.verifiedEmail);
    return await input.walletAuthMethods.resolveActiveEmailOtpAuthorityForUnlock({
      walletId: input.request.walletId,
      walletAuthMethodId: input.request.walletAuthMethodId,
      providerUserId: input.request.providerUserId,
      emailHashHex,
    });
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      code: 'internal',
      message: error instanceof Error ? error.message : 'Email OTP authority resolution failed',
    };
  }
}

async function issueWalletSessionForActiveAuthority(input: {
  readonly resolved: ActiveWalletUnlockAuthorityResolution;
  readonly authorizationService: AuthorizationService;
  readonly orgId: string;
  readonly verifiedChallengeId: string;
  readonly walletSessionClientCapability: WalletSessionClientCapabilityV1;
}): Promise<WalletUnlockPasskeySessionResolution> {
  const tenantId = parseTenantId(input.orgId);
  const principalId = parsePrincipalId(
    'walletAuthAuthority' in input.resolved
      ? input.resolved.walletAuthAuthority.factor.providerUserId
      : String(input.resolved.authority.walletId),
  );
  const mintId = parseReusableWalletSessionMintId(input.verifiedChallengeId);
  if (!tenantId.ok || !principalId.ok || !mintId.ok) {
    return {
      kind: 'rejected',
      code: 'invalid_state',
      message: 'Linked-device Wallet Session identity is invalid',
    };
  }

  const issuedAtMs = Date.now();
  const deviceLinked = input.resolved.authority.provenance.kind === 'device_link';
  try {
    const directIssue = await input.authorizationService.issueDirectWalletSessionAuthorizationV2({
      tenantId: tenantId.value,
      principalId: principalId.value,
      walletId: input.resolved.authority.walletId,
      authority: input.resolved.authority,
      walletAuthMethodId: input.resolved.authMethod.walletAuthMethodId,
      mintId: mintId.value,
      remainingUses: deviceLinked
        ? LINKED_DEVICE_WALLET_SESSION_REMAINING_USES
        : DEFAULT_WALLET_SESSION_REMAINING_USES,
      issuedAtMs,
      expiresAtMs:
        issuedAtMs +
        (deviceLinked ? LINKED_DEVICE_WALLET_SESSION_TTL_MS : DEFAULT_WALLET_SESSION_TTL_MS),
      walletSessionClientCapability: input.walletSessionClientCapability,
      responseFamily: WALLET_UNLOCK_EXACT_RESPONSE_FAMILY_V1,
    });
    const authorityProvenanceKind = input.resolved.authority.provenance.kind;
    if (authorityProvenanceKind === 'wallet_registration') {
      return {
        kind: 'rejected',
        code: 'invalid_state',
        message: 'Founding authority entered additive Wallet Session issuance',
      };
    }
    if (directIssue.kind === 'already_committed') {
      return {
        kind: 'already_committed',
        authorityProvenanceKind,
        committed: directIssue,
      };
    }
    if (directIssue.kind === 'protocol_mismatch') {
      return {
        kind: 'rejected',
        code: directIssue.code,
        message: directIssue.message,
      };
    }
    return {
      kind: 'active_authority',
      authorityProvenanceKind,
      walletSession: issuedWalletSessionAuthorizationV2(directIssue),
      operationCredential: directIssue.operationCredential,
    };
  } catch (error: unknown) {
    return {
      kind: 'rejected',
      code: 'internal',
      message: error instanceof Error ? error.message : 'Wallet Session issuance failed',
    };
  }
}

function issuedWalletSessionAuthorizationV2(
  directIssue: Extract<DirectV2IssueResult, { readonly kind: 'issued' }>,
): IssuedWalletSessionAuthorizationV2 {
  return {
    session: directIssue.session,
    quota: directIssue.quota,
  };
}

async function issueWalletSessionForPasskeyUnlock(input: {
  readonly walletAuthMethods: Pick<
    CloudflareD1WalletAuthMethodService,
    'resolveActivePasskeyAuthorityForUnlock'
  >;
  readonly authorizationService: AuthorizationService;
  readonly orgId: string;
  readonly request: Parameters<
    RouterApiServiceBag['walletUnlock']['issueWalletSessionForPasskeyUnlock']
  >[0];
}): Promise<WalletUnlockPasskeySessionResolution> {
  const resolved = await input.walletAuthMethods.resolveActivePasskeyAuthorityForUnlock(
    input.request,
  );
  if (resolved.kind !== 'active_authority') {
    return {
      kind: 'rejected',
      code: resolved.code,
      message: resolved.message,
    };
  }
  if (resolved.authority.provenance.kind === 'wallet_registration') {
    return { kind: 'wallet_registration' };
  }
  return await issueWalletSessionForActiveAuthority({
    resolved,
    authorizationService: input.authorizationService,
    orgId: input.orgId,
    verifiedChallengeId: input.request.verifiedChallengeId,
    walletSessionClientCapability: input.request.walletSessionClientCapability,
  });
}

async function issueWalletSessionForEmailOtpUnlock(input: {
  readonly walletAuthMethods: Pick<
    CloudflareD1WalletAuthMethodService,
    'resolveActiveEmailOtpAuthorityForUnlock'
  >;
  readonly emailOtpRecoveryService: Pick<
    CloudflareD1EmailOtpRecoveryService,
    'readEmailOtpEnrollment'
  >;
  readonly authorizationService: AuthorizationService;
  readonly request: Parameters<
    RouterApiServiceBag['walletUnlock']['issueWalletSessionForEmailOtpUnlock']
  >[0];
}): Promise<WalletUnlockPasskeySessionResolution> {
  const resolved = await resolveEmailOtpAuthorityForUnlock({
    walletAuthMethods: input.walletAuthMethods,
    emailOtpRecoveryService: input.emailOtpRecoveryService,
    request: input.request,
  });
  if (resolved.kind === 'rejected') {
    return {
      kind: 'rejected',
      code: resolved.code,
      message: resolved.message,
    };
  }
  if (resolved.authority.provenance.kind === 'wallet_registration') {
    return { kind: 'wallet_registration' };
  }
  return await issueWalletSessionForActiveAuthority({
    resolved,
    authorizationService: input.authorizationService,
    orgId: input.request.orgId,
    verifiedChallengeId: input.request.verifiedChallengeId,
    walletSessionClientCapability: input.request.walletSessionClientCapability,
  });
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
    resolveEmailOtpAuthorityForUnlock: (request) =>
      resolveEmailOtpAuthorityForUnlock({
        walletAuthMethods: assembly.walletAuthMethods,
        emailOtpRecoveryService: assembly.emailOtpRecoveryService,
        request,
      }),
    issueWalletSessionForPasskeyUnlock: (request) =>
      issueWalletSessionForPasskeyUnlock({
        walletAuthMethods: assembly.walletAuthMethods,
        authorizationService: assembly.authorizationService,
        orgId: assembly.options.orgId,
        request,
      }),
    issueWalletSessionForEmailOtpUnlock: (request) =>
      issueWalletSessionForEmailOtpUnlock({
        walletAuthMethods: assembly.walletAuthMethods,
        emailOtpRecoveryService: assembly.emailOtpRecoveryService,
        authorizationService: assembly.authorizationService,
        request,
      }),
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
    issueDirectWalletSessionAuthorizationV2:
      assembly.authorizationService.issueDirectWalletSessionAuthorizationV2.bind(
        assembly.authorizationService,
      ),
    issueReusableWalletSession: assembly.authorizationService.issueReusableWalletSession.bind(
      assembly.authorizationService,
    ),
    issueWalletSessionAuthorizationV2FromReusableSession:
      assembly.authorizationService.issueWalletSessionAuthorizationV2FromReusableSession.bind(
        assembly.authorizationService,
      ),
    issueOpaqueWalletSessionToken: assembly.authorizationService.issueOpaqueWalletSessionToken.bind(
      assembly.authorizationService,
    ),
    issueRegistrationReplayOpaqueWalletSessionToken:
      assembly.authorizationService.issueRegistrationReplayOpaqueWalletSessionToken.bind(
        assembly.authorizationService,
      ),
    resolveOpaqueWalletSessionToken:
      assembly.authorizationService.resolveOpaqueWalletSessionToken.bind(
        assembly.authorizationService,
      ),
    readWalletSessionAuthorizationV2ByOperationCredential: async (input) => {
      const authorization =
        await assembly.authorizationService.readWalletSessionAuthorizationV2ByOperationCredential(
          input,
        );
      if (!authorization) return null;
      const authority = await assembly.walletAuthorityStore.readById(
        authorization.session.authorityId,
      );
      const authMethod = await assembly.walletAuthMethodStore.readByIdV2({
        walletAuthMethodId: authorization.session.walletAuthMethodId,
      });
      if (
        !authority ||
        authority.state !== 'active' ||
        !authMethod ||
        authMethod.status !== 'active'
      ) {
        return null;
      }
      return {
        authorization,
        authority,
        authMethod,
        retiredAtMs: null,
      };
    },
    readReusableWalletSessionStatus:
      assembly.authorizationService.readReusableWalletSessionStatus.bind(
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
      orgId: assembly.options.orgId,
      passkeyCustodyEnvelopes: assembly.passkeyCustodyEnvelopes,
      walletCustodyCommits: assembly.walletCustodyCommitStore,
      walletStore: assembly.walletStore,
      walletAuthorityStore: assembly.walletAuthorityStore,
      webAuthnStore: assembly.webAuthnStore,
      googleRecovery: assembly.walletRecoveryGoogleEmailOtp,
      emailOtpRegistrationEnrollmentFinalizer: assembly.emailOtpRegistrationEnrollmentFinalizer,
      logger: normalizeLogger(),
    }),
    executeSignedDelegate: assembly.signedDelegateExecutor.execute.bind(
      assembly.signedDelegateExecutor,
    ),
    ...(assembly.deviceLinking === undefined ? {} : { deviceLinking: assembly.deviceLinking }),
    ...(assembly.deviceManagement === undefined
      ? {}
      : { deviceManagement: assembly.deviceManagement }),
    ...(assembly.deviceLinkingOwnerAuthorization === undefined
      ? {}
      : { deviceLinkingOwnerAuthorization: assembly.deviceLinkingOwnerAuthorization }),
  };
}
