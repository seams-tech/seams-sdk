import type {
  ActiveWalletAuthorityV1,
  PendingWalletAuthorityV1,
  WalletAuthorityV1,
  WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildPendingWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  walletAuthorityDigestsMatchV1,
} from '@shared/authorization/walletAuthority';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type LinkDeviceSessionId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import {
  parsePrincipalId,
  parseWalletSessionMintId,
  parseTenantId,
  type PrincipalId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  buildDelegatedWalletAuthorityV1,
  parseDelegatedWalletPermissionSetV1,
  validateDelegatedWalletAuthorityAttenuationV1,
} from '@shared/authorization/delegatedAuthority';
import {
  computeCommittedSignerPackageSetDigestB64u,
  parseCommittedAuthorityPackagesV1,
  type CommittedAuthorityPackagesV1,
  type CommittedEcdsaSignerPackageV1,
  type CommittedEd25519SignerPackageV1,
  type CommittedSignerPackageSetV1,
} from '@shared/device-linking/committedSignerPackages';
import {
  buildAuthorityActiveSessionRecordV1,
  buildAuthorityPendingLocalInstallSessionRecordV1,
  type LinkedDeviceSessionRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceSession';
import type {
  LocalAuthorityActivationFinalAckV1,
  LocalAuthorityInstallationReceiptV1,
  OrdinarySignerMaterialRecipientRequestV1,
  LinkedDeviceOrdinaryMaterialSourceContributionV1,
  OrdinarySignerMaterialReservationPreparationV1 as SharedOrdinarySignerMaterialReservationPreparationV1,
  VerifiedLinkInputV1,
} from '@shared/device-linking/contracts';
import {
  buildLinkedDeviceWalletSessionCredentialDeliveryBindingV1,
  computeLinkedDeviceWalletSessionCredentialDeliveryAadDigestB64u,
  computeLinkedDeviceWalletSessionCredentialEnvelopeDigestB64u,
  encodeLinkedDeviceWalletSessionCredentialDeliveryAadV1,
  assertLinkedDeviceWalletSessionCredentialDeliveryIntegrityV1,
  parseLinkedDeviceWalletSessionCredentialDeliveryV1,
  parseLinkedDeviceActivationCleanupReceiptV1,
  type LinkedDeviceWalletSessionCredentialDeliveryAadV1,
  type LinkedDeviceWalletSessionCredentialDeliveryBindingV1,
  type LinkedDeviceWalletSessionCredentialDeliveryV1,
  type LinkedDeviceActivationCleanupReceiptV1,
} from '@shared/device-linking/walletSessionCredentialDelivery';
import { type ExactAdministeredSignerV1 } from '@shared/device-linking/delegatedActivationPlan';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { parseLinkDeviceSessionId, parseWalletKeyId } from '@shared/signing-lanes/ids';
import {
  OrdinaryInactiveSignerMaterialReservationServiceV1,
  type OrdinaryEcdsaSignerMaterialReservationPreparationV1,
  type OrdinaryEd25519SignerMaterialReservationPreparationV1,
  type OrdinaryEcdsaSignerMaterialReservationV1,
  type OrdinaryEd25519SignerMaterialReservationV1,
} from '../../../../core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  parseLinkedDeviceEcdsaSourceContributionPackageV1,
  parseLinkedDeviceEcdsaSourceDerivationV1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionV1,
} from '@shared/device-linking/sourceContribution';
import type { LinkedDeviceEcdsaSourcePreservingActivationReceiptV1 } from '@shared/device-linking/sourceContribution';
import { parseLocalAuthorityActivationFinalAckV1 } from '@shared/device-linking/parsers';
import {
  computeWalletSessionInstallationReceiptDigestB64u,
  computeWalletSessionOperationCredentialDigestB64u,
} from '@shared/device-linking/digests';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import {
  parseRouterAbEd25519YaoApplicationBindingFactsV1,
  parseRouterAbEd25519YaoCeremonyBindingV1,
  type RouterAbEd25519YaoActivationPublicReceiptV1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
} from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { d1ChangedRows, parseD1JsonColumn } from '../../../../storage/d1Sql';
import {
  D1WalletAuthorityStore,
  type D1WalletAuthorityStoreScope,
} from '../wallet/d1WalletAuthorityStore';
import type { D1LinkedDeviceSessionStoreV1 } from './d1LinkedDeviceSessionStore';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import type { WalletEd25519SignerRecord } from '../../../../core/WalletStore';
import type {
  AuthorizationService,
  IssueWalletSessionAuthorizationV2Input,
} from '../../../../authorization/service';
import {
  buildPersistedActiveWalletSessionAuthorizationV2,
  type PersistedActiveWalletSessionAuthorizationV2,
  type IssuedWalletSessionAuthorizationV2,
} from '../../../../authorization/domain';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { assertLinkedDeviceOrdinaryMaterialSourceContributionMatchesContextV1 } from '@shared/device-linking/sourceContribution';
import { linkedDeviceX25519RecipientPublicKeyB64uV1 } from './d1LinkedDeviceSourceContributionPreparationPlanner';
import { computeLinkedDevicePublicKeyDigestV1 } from '../../../../core/deviceLinking/requestProof';
import { prepareD1WebAuthnAuthenticatorInsertStatement } from '../webauthn/d1WebAuthnStore';
import {
  prepareD1WebAuthnCredentialBindingInsertStatement,
  type WebAuthnCredentialBindingRecord,
} from '../../../../core/WebAuthnCredentialBindingStore';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import type { CloudflareD1EmailOtpRegistrationEnrollmentFinalizer } from '../emailOtp/d1EmailOtpRegistrationEnrollmentFinalizer';

type ExactSigner = ExactAdministeredSignerV1;

type ListWalletEd25519SignersV1 = (
  walletId: WalletId,
) => Promise<readonly WalletEd25519SignerRecord[]>;

type WorkerOrdinarySignerMaterialReservationPreparationV1 =
  | {
      readonly keyFamily: 'ed25519';
      readonly preparation: OrdinaryEd25519SignerMaterialReservationPreparationV1;
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly preparation: OrdinaryEcdsaSignerMaterialReservationPreparationV1;
    };

/** The only worker authority mutation accepted by the linked-device cutover. */
export type OrdinaryInactiveSignerMaterialActivationPortV1 = {
  activateOrdinaryInactiveSignerMaterialV1(input: {
    readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
    readonly reservationId: string;
    readonly materialActivation: MpcMaterialActivationRef;
    readonly activatedAtMs: number;
    readonly preparation: WorkerOrdinarySignerMaterialReservationPreparationV1;
  }): Promise<void>;
};

export type D1LinkedDeviceAuthorityInstallServiceOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletAuthorityStoreScope;
  readonly authorityStore: D1WalletAuthorityStore;
  readonly authMethodStore: Pick<D1WalletAuthMethodStore, 'readByIdV2'>;
  /** The wallet's ordinary Ed25519 signer rows are the source of NEAR identity facts. */
  readonly listWalletEd25519Signers: ListWalletEd25519SignersV1;
  readonly sessionStore: Pick<
    D1LinkedDeviceSessionStoreV1,
    | 'buildAuthorityPendingLocalInstallCasStatementsV1'
    | 'buildAuthorityActivationCasStatementsV1'
    | 'deleteActiveSessionWithStatementsV1'
  >;
  readonly sessionService: {
    getSessionV1(input: {
      readonly linkSessionId: LinkDeviceSessionId;
      readonly nowMs: number;
    }): Promise<LinkedDeviceSessionRecordV1 | null>;
    deleteActiveSessionV1(input: {
      readonly linkSessionId: LinkDeviceSessionId;
      readonly expectedRevision: number;
      readonly authorityId: WalletAuthorityId;
      readonly packageSetDigestB64u: DigestB64u;
      readonly nowMs: number;
    }): Promise<
      | { readonly outcome: 'applied' | 'replayed' | 'deleted' }
      | { readonly outcome: string; readonly message?: string }
    >;
  };
  readonly reservationService: OrdinaryInactiveSignerMaterialReservationServiceV1;
  readonly materialActivation: OrdinaryInactiveSignerMaterialActivationPortV1;
  readonly authorizationService: Pick<
    AuthorizationService,
    | 'prepareWalletSessionAuthorizationV2'
    | 'readWalletSessionAuthorizationV2ByMint'
  >;
  readonly authorizationStore: {
    prepareDirectWalletSessionAuthorizationV2Statements(
      persisted: PersistedActiveWalletSessionAuthorizationV2,
    ): readonly [
      D1PreparedStatementLike,
      D1PreparedStatementLike,
      D1PreparedStatementLike,
      D1PreparedStatementLike,
      D1PreparedStatementLike,
      D1PreparedStatementLike,
    ];
  };
  /** Supplies first-Email enrollment statements for the new linked target branch. */
  readonly emailOtpEnrollmentFinalizer?: Pick<
    CloudflareD1EmailOtpRegistrationEnrollmentFinalizer,
    'prepareLinkedDeviceEnrollment'
  >;
  readonly tenantId: TenantId;
  readonly walletSessionTtlMs?: number;
  readonly walletSessionRemainingUses?: number;
  readonly nowV1?: () => number;
};

export type CommitPendingAuthorityInputV1 = VerifiedLinkInputV1 & {
  readonly nowMs: number;
  readonly ed25519ExportRootPackage: CommittedAuthorityPackagesV1['ed25519ExportRootPackage'];
};

export type CommitPendingAuthorityResultV1 =
  | {
      readonly kind: 'committed' | 'replayed';
      readonly packages: CommittedAuthorityPackagesV1;
      readonly ordinarySignerMaterialPreparations: readonly [
        SharedOrdinarySignerMaterialReservationPreparationV1,
        ...SharedOrdinarySignerMaterialReservationPreparationV1[],
      ];
      readonly session: LinkedDeviceSessionRecordV1;
    }
  | { readonly kind: 'conflict'; readonly message: string }
  | { readonly kind: 'invalid_input'; readonly message: string };

export type ActivateInstalledAuthorityResultV1 =
  | {
      readonly kind: 'active';
      readonly outcome: 'activated' | 'replayed';
      readonly authority: ActiveWalletAuthorityV1;
      readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
      readonly session: LinkedDeviceSessionRecordV1;
      readonly walletSession: IssuedWalletSessionAuthorizationV2;
      readonly deliveryBinding: LinkedDeviceWalletSessionCredentialDeliveryBindingV1;
      readonly sealedDelivery: LinkedDeviceWalletSessionCredentialDeliveryV1;
    }
  | {
      readonly kind: 'pending_local_install';
      readonly authorityId: WalletAuthorityId;
      readonly reason: 'server_worker_activation_pending' | 'wallet_session_issuance_pending';
    }
  | { readonly kind: 'integrity_error'; readonly message: string };

type InstalledAuthorityActivationStageV1 =
  | 'receipt_validation'
  | 'server_worker_activation'
  | 'authority_activation'
  | 'wallet_session_issuance';

class LinkedDeviceActivationIntegrityErrorV1 extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LinkedDeviceActivationIntegrityErrorV1';
  }
}

export type LocalAuthorityActivationAcknowledgementAuthenticationV1 =
  | {
      readonly kind: 'live';
      readonly session: LinkedDeviceSessionRecordV1;
    }
  | {
      readonly kind: 'cleanup_receipt';
      readonly receipt: LinkedDeviceActivationCleanupReceiptV1;
    }
  | {
      /** Exact-method unlock can replay after the QR session is gone. */
      readonly kind: 'exact_wallet_session';
      readonly tenantId: TenantId;
      readonly principalId: PrincipalId;
      readonly walletId: WalletId;
      readonly authorityId: WalletAuthorityId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly expiresAtMs: number;
    };

type StoredInstallationRow = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly authMethodId: WalletAuthMethodId;
  readonly deviceId: DeviceId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly targetFactorVerifiedAtMs: number;
  readonly sourceManifestDigestB64u: DigestB64u;
  /** Null is accepted only for legacy rows created before migration 0033. */
  readonly deliveryRecipientPublicKey65B64u: string | null;
  readonly packages: CommittedAuthorityPackagesV1;
  readonly serverReservationIds: Readonly<{
    readonly ed25519?: ServerReservationRecordV1<'ed25519'>;
    readonly ecdsa_secp256k1?: ServerReservationRecordV1<'ecdsa_secp256k1'>;
  }>;
  readonly installedRecordSetDigestB64u: DigestB64u | null;
  readonly activatedAtMs: number | null;
};

export type InstalledLinkedDeviceEd25519AuthorityProjectionV1 = {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly deviceId: DeviceId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly targetBinding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly targetSessionId: RouterAbEd25519YaoCeremonyBindingV1['lifecycle']['session_id'];
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly participantIds: readonly [number, number];
  readonly activationReceipt: RouterAbEd25519YaoActivationPublicReceiptV1;
  readonly installedRecordSetDigestB64u: DigestB64u;
  readonly activatedAtMs: number;
};

export type InstalledLinkedDeviceEcdsaAuthorityProjectionV1 = {
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly deviceId: DeviceId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly signer: Extract<ExactSigner, { readonly keyFamily: 'ecdsa_secp256k1' }>;
  readonly activationReceipt: LinkedDeviceEcdsaSourcePreservingActivationReceiptV1;
  readonly installedRecordSetDigestB64u: DigestB64u;
  readonly activatedAtMs: number;
};

type AuthorityAllocation = {
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly enrollmentId: string;
  readonly deviceId: DeviceId;
};

type AuthorityAllocationPreparation = {
  readonly authorityId: WalletAuthorityId;
  readonly statement: D1PreparedStatementLike | null;
};

type ServerReservationRecordV1<F extends 'ed25519' | 'ecdsa_secp256k1'> = {
  readonly reservationId: string;
  readonly preparation: Extract<
    WorkerOrdinarySignerMaterialReservationPreparationV1,
    { readonly keyFamily: F }
  >['preparation'];
};

export class D1LinkedDeviceAuthorityInstallServiceV1 {
  private readonly nowV1: () => number;

  constructor(private readonly options: D1LinkedDeviceAuthorityInstallServiceOptionsV1) {
    this.nowV1 = options.nowV1 ?? Date.now;
  }

  async commitPendingAuthorityV1(
    input: CommitPendingAuthorityInputV1,
  ): Promise<CommitPendingAuthorityResultV1> {
    try {
      const nowMs = requireTime(input.nowMs, 'nowMs');
      const session = await this.options.sessionService.getSessionV1({
        linkSessionId: input.linkSessionId,
        nowMs,
      });
      if (!session) return { kind: 'conflict', message: 'linked-device session was not found' };
      const sourceContributionPreparation = requireSourceContributionPreparations(session);
      await validateVerifiedLinkInput(
        input,
        nowMs,
        this.options.authMethodStore,
        sourceContributionPreparation,
      );
      const existing = await this.readInstallation(input.linkSessionId);
      const allocation = await this.prepareAuthorityAllocation(input, existing);
      const expectedAuthorityId = allocation.authorityId;
      if (existing) {
        await assertStoredPackageDigest(existing);
        assertRetryInput(existing, input, expectedAuthorityId);
        if (allocation.statement) {
          await this.options.database.batch([allocation.statement]);
        }
        if (
          session.state.state !== 'authority_pending_local_install' &&
          session.state.state !== 'active'
        ) {
          return {
            kind: 'conflict',
            message: 'stored authority installation has no pending session',
          };
        }
        return {
          kind: 'replayed',
          packages: existing.packages,
          ordinarySignerMaterialPreparations: sourceContributionPreparation,
          session,
        };
      }
      if (session.state.state !== 'provisioning') {
        return { kind: 'conflict', message: `linked-device session is ${session.state.state}` };
      }

      const authorityId = expectedAuthorityId;
      const emailOtpEnrollmentStatements = await this.prepareEmailOtpEnrollmentStatements(input);
      const reservations = await this.reserveSignerMaterial(input, sourceContributionPreparation);
      const activationSet = buildActivationSet(input.signerManifest, reservations);
      const pendingAuthMethod = buildPendingAuthMethod(input, authorityId, nowMs);
      const sourceManifestDigestB64u = await digestJson(input.signerManifest);
      const packageSetDigestB64u = await computeCommittedSignerPackageSetDigestB64u({
        authorityId,
        walletId: input.walletId,
        enrollmentId: input.enrollmentId,
        linkSessionId: input.linkSessionId,
        deviceId: input.targetDeviceId,
        authMethodId: pendingAuthMethod.walletAuthMethodId,
        permissions: input.permissions,
        sourceManifestDigestB64u,
        signerPackages: reservations.packages,
        ed25519ExportRootPackageDigestB64u: input.ed25519ExportRootPackage
          ? await digestJson(input.ed25519ExportRootPackage)
          : null,
        targetFactorVerificationDigestB64u: input.targetFactor.verificationDigestB64u,
      });
      const pendingAuthority = await buildPendingAuthority({
        authorityId,
        input,
        activationSet,
        packageSetDigestB64u,
        nowMs,
      });
      const packages: CommittedAuthorityPackagesV1 = {
        kind: 'committed_authority_packages_v1',
        authority: pendingAuthority,
        authMethod: pendingAuthMethod,
        signerPackages: reservations.packages,
        ed25519ExportRootPackage: input.ed25519ExportRootPackage,
        packageSetDigestB64u,
      };
      const nextSession = buildAuthorityPendingLocalInstallSessionRecordV1({
        record: session,
        authorityId,
        packageSetDigestB64u,
        nowMs,
      });
      const packageStatement = await this.buildInstallationInsertStatement({
        input,
        packages,
        serverReservationIds: reservations.serverReservationIds,
        nowMs,
      });
      const sessionStatements =
        this.options.sessionStore.buildAuthorityPendingLocalInstallCasStatementsV1({
          linkSessionId: session.linkSessionId,
          expectedRevision: session.revision,
          nextRecord: nextSession,
          nowMs,
        });
      const committed = await this.options.authorityStore.commitPendingAuthorityWithStatements(
        { authority: pendingAuthority, authMethod: pendingAuthMethod },
        [
          ...(allocation.statement ? [allocation.statement] : []),
          ...emailOtpEnrollmentStatements,
          packageStatement,
          ...sessionStatements,
        ],
      );
      if (committed.kind === 'conflict') {
        const replay = await this.readInstallation(input.linkSessionId);
        if (replay) {
          await assertStoredPackageDigest(replay);
          const replaySession = await this.options.sessionService.getSessionV1({
            linkSessionId: input.linkSessionId,
            nowMs,
          });
          if (replaySession) {
            return {
              kind: 'replayed',
              packages: replay.packages,
              ordinarySignerMaterialPreparations: sourceContributionPreparation,
              session: replaySession,
            };
          }
        }
        return {
          kind: 'conflict',
          message: 'wallet authority commit conflicts with an existing record',
        };
      }
      if (committed.kind === 'replayed') {
        const replay = await this.readInstallation(input.linkSessionId);
        if (!replay) return { kind: 'conflict', message: 'authority replay package is missing' };
        await assertStoredPackageDigest(replay);
        const replaySession = await this.options.sessionService.getSessionV1({
          linkSessionId: input.linkSessionId,
          nowMs,
        });
        if (!replaySession)
          return { kind: 'conflict', message: 'authority replay session is missing' };
        return {
          kind: 'replayed',
          packages: replay.packages,
          ordinarySignerMaterialPreparations: sourceContributionPreparation,
          session: replaySession,
        };
      }
      return {
        kind: 'committed',
        packages,
        ordinarySignerMaterialPreparations: reservations.ordinarySignerMaterialPreparations,
        session: nextSession,
      };
    } catch (error: unknown) {
      return { kind: 'invalid_input', message: errorMessage(error) };
    }
  }

  async activateInstalledAuthorityV1(input: {
    readonly receipt: LocalAuthorityInstallationReceiptV1;
    readonly nowMs?: number;
  }): Promise<ActivateInstalledAuthorityResultV1> {
    let stage: InstalledAuthorityActivationStageV1 = 'receipt_validation';
    try {
      const nowMs = requireTime(input.nowMs ?? this.nowV1(), 'nowMs');
      const receipt = input.receipt;
      const stored = await this.readInstallationByAuthority(receipt.authorityId);
      if (!stored)
        return { kind: 'integrity_error', message: 'authority installation was not found' };
      await assertStoredPackageDigest(stored);
      assertReceiptMatchesInstallation(receipt, stored, nowMs);
      const session = await this.options.sessionService.getSessionV1({
        linkSessionId: stored.linkSessionId,
        nowMs,
      });
      if (!session)
        return { kind: 'integrity_error', message: 'linked-device session was not found' };
      const authority = await this.options.authorityStore.readById(stored.authorityId);
      const authMethod = await this.options.authMethodStore.readByIdV2({
        walletAuthMethodId: stored.authMethodId,
      });
      if (!authority || !authMethod)
        return { kind: 'integrity_error', message: 'pending authority records are missing' };
      if (
        !sameAuthority(authority, stored.packages.authority) ||
        !sameAuthMethod(authMethod, stored.packages.authMethod)
      ) {
        return {
          kind: 'integrity_error',
          message: 'pending authority records do not match committed packages',
        };
      }
      if (
        authority.state === 'active' &&
        authMethod.status === 'active' &&
        session.state.state === 'active'
      ) {
        stage = 'wallet_session_issuance';
        const activeSession = await this.options.sessionService.getSessionV1({
          linkSessionId: stored.linkSessionId,
          nowMs,
        });
        if (
          !activeSession ||
          activeSession.state.state !== 'active' ||
          activeSession.state.authorityId !== authority.authorityId ||
          activeSession.packageSetDigestB64u !== stored.packageSetDigestB64u
        ) {
          throw new LinkedDeviceActivationIntegrityErrorV1(
            'linked-device authority replay did not retain an active session',
          );
        }
        const walletSession = await this.readCommittedWalletSession(
          authority,
          authMethod,
          receipt.installedAtMs,
        );
        const sealedDelivery = await this.readCredentialDelivery(stored.linkSessionId);
        if (!sealedDelivery) {
          throw new LinkedDeviceActivationIntegrityErrorV1(
            'linked-device Wallet Session credential delivery is missing',
          );
        }
        await this.assertCredentialDeliveryMatchesCommittedSession({
          stored,
          receipt,
          walletSession,
          delivery: sealedDelivery,
        });
        return {
          kind: 'active',
          outcome: 'replayed',
          authority,
          authMethod,
          session: activeSession,
          walletSession,
          deliveryBinding: buildLinkedDeviceWalletSessionCredentialDeliveryBindingV1(
            sealedDelivery.aad,
          ),
          sealedDelivery,
        };
      }
      if (
        authority.state !== 'pending_local_install' ||
        authMethod.status !== 'pending_local_install' ||
        session.state.state !== 'authority_pending_local_install'
      ) {
        return { kind: 'integrity_error', message: 'authority activation state is inconsistent' };
      }
      if (!stored.deliveryRecipientPublicKey65B64u) {
        throw new LinkedDeviceActivationIntegrityErrorV1(
          'linked-device installation has no credential delivery recipient',
        );
      }
      const activeAuthority = await buildActiveAuthority(authority, receipt.installedAtMs);
      const activeAuthMethod = buildActiveAuthMethod(authMethod, receipt.installedAtMs);
      const passkeyCredentialStatements = await buildPasskeyCredentialPromotionStatements({
        database: this.options.database,
        scope: this.options.scope,
        listWalletEd25519Signers: this.options.listWalletEd25519Signers,
        authority: activeAuthority,
        authMethod: activeAuthMethod,
        activatedAtMs: receipt.installedAtMs,
      });
      stage = 'server_worker_activation';
      await this.activateReservations(stored, receipt.installedAtMs);
      stage = 'wallet_session_issuance';
      const nextSession = buildAuthorityActiveSessionRecordV1({
        record: session,
        activatedAtMs: receipt.installedAtMs,
        nowMs,
      });
      const sessionStatements = this.options.sessionStore.buildAuthorityActivationCasStatementsV1({
        linkSessionId: session.linkSessionId,
        expectedRevision: session.revision,
        nextRecord: nextSession,
        nowMs,
      });
      const preparedWalletSession =
        await this.options.authorizationService.prepareWalletSessionAuthorizationV2(
          this.buildWalletSessionAuthorizationInput(
            activeAuthority,
            activeAuthMethod,
            receipt.installedAtMs,
          ),
        );
      const operationCredential = {
        kind: 'opaque_wallet_session_operation_credential_v1' as const,
        token: `wst_${secureRandomBase64Url(32, 'linked-device Wallet Session operation credential')}`,
        walletSessionId: preparedWalletSession.session.walletSessionId,
      };
      const credentialDigestB64u =
        await computeWalletSessionOperationCredentialDigestB64u(operationCredential);
      const walletSessionStatements =
        this.options.authorizationStore.prepareDirectWalletSessionAuthorizationV2Statements(
          buildPersistedActiveWalletSessionAuthorizationV2({
            session: preparedWalletSession.session,
            quota: preparedWalletSession.quota,
            primaryOperationCredentialDigestB64u: credentialDigestB64u,
          }),
        );
      const installationReceiptDigestB64u =
        await computeWalletSessionInstallationReceiptDigestB64u(receipt);
      const sealedDelivery = await sealLinkedDeviceWalletSessionCredentialV1({
        scope: this.options.scope,
        tenantId: this.options.tenantId,
        linkSessionId: stored.linkSessionId,
        authorityId: activeAuthority.authorityId,
        walletId: activeAuthority.walletId,
        walletAuthMethodId: activeAuthMethod.walletAuthMethodId,
        authorizationId: preparedWalletSession.session.authorizationId,
        walletSessionId: preparedWalletSession.session.walletSessionId,
        quotaId: preparedWalletSession.quota.quotaId,
        principalId: preparedWalletSession.session.principalId,
        credentialDigestB64u,
        recipientPublicKey65B64u: stored.deliveryRecipientPublicKey65B64u,
        issuedAtMs: preparedWalletSession.session.createdAtMs,
        expiresAtMs: preparedWalletSession.session.expiresAtMs,
        installationReceiptDigestB64u,
        operationCredential,
      });
      const installationActivationStatement = this.buildInstallationActivationStatement({
        stored,
        receipt,
      });
      const deliveryStatement = this.buildCredentialDeliveryInsertStatement(sealedDelivery);
      stage = 'authority_activation';
      const activation = await this.options.authorityStore.activatePendingAuthorityWithStatements(
        {
          pendingAuthority: authority,
          activeAuthority,
          pendingAuthMethod: authMethod,
          activeAuthMethod,
        },
        [
          ...sessionStatements,
          ...walletSessionStatements,
          installationActivationStatement,
          deliveryStatement,
          ...passkeyCredentialStatements,
        ],
      );
      if (activation.kind === 'conflict') {
        const replay = await this.readActivationReplayAfterCasRace({
          stored,
          receipt,
          expectedPendingAuthority: authority,
          expectedPendingAuthMethod: authMethod,
          nowMs,
        });
        if (replay) return replay;
        return {
          kind: 'integrity_error',
          message: 'authority activation conflicts with another transition',
        };
      }
      const persistedSession =
        activation.kind === 'replayed'
          ? await this.options.sessionService.getSessionV1({
              linkSessionId: stored.linkSessionId,
              nowMs,
            })
          : nextSession;
      if (
        !persistedSession ||
        persistedSession.state.state !== 'active' ||
        persistedSession.state.authorityId !== activation.authority.authorityId ||
        persistedSession.packageSetDigestB64u !== stored.packageSetDigestB64u
      ) {
        throw new LinkedDeviceActivationIntegrityErrorV1(
          'linked-device authority activation replay did not commit an active session',
        );
      }
      stage = 'wallet_session_issuance';
      const walletSession = await this.readCommittedWalletSession(
        activation.authority,
        activation.authMethod,
        receipt.installedAtMs,
      );
      const persistedDelivery =
        activation.kind === 'replayed'
          ? await this.readCredentialDelivery(stored.linkSessionId)
          : sealedDelivery;
      if (!persistedDelivery) {
        throw new LinkedDeviceActivationIntegrityErrorV1(
          'linked-device Wallet Session credential delivery is missing',
        );
      }
      return {
        kind: 'active',
        outcome: activation.kind === 'replayed' ? 'replayed' : 'activated',
        authority: activation.authority,
        authMethod: activation.authMethod,
        session: persistedSession,
        walletSession,
        deliveryBinding: buildLinkedDeviceWalletSessionCredentialDeliveryBindingV1(
          persistedDelivery.aad,
        ),
        sealedDelivery: persistedDelivery,
      };
    } catch (error: unknown) {
      if (error instanceof LinkedDeviceActivationIntegrityErrorV1) {
        return { kind: 'integrity_error', message: error.message };
      }
      if (stage === 'server_worker_activation') {
        return {
          kind: 'pending_local_install',
          authorityId: input.receipt.authorityId,
          reason: 'server_worker_activation_pending',
        };
      }
      if (stage === 'wallet_session_issuance') {
        return {
          kind: 'pending_local_install',
          authorityId: input.receipt.authorityId,
          reason: 'wallet_session_issuance_pending',
        };
      }
      return { kind: 'integrity_error', message: errorMessage(error) };
    }
  }

  private async readActivationReplayAfterCasRace(input: {
    readonly stored: StoredInstallationRow;
    readonly receipt: LocalAuthorityInstallationReceiptV1;
    readonly expectedPendingAuthority: PendingWalletAuthorityV1;
    readonly expectedPendingAuthMethod: Extract<
      WalletAuthMethodRecordV2,
      { readonly status: 'pending_local_install' }
    >;
    readonly nowMs: number;
  }): Promise<Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }> | null> {
    const authority = await this.options.authorityStore.readById(input.stored.authorityId);
    const authMethod = await this.options.authMethodStore.readByIdV2({
      walletAuthMethodId: input.stored.authMethodId,
    });
    if (!authority || !authMethod) return null;
    const expectedAuthority = await buildActiveAuthority(
      input.expectedPendingAuthority,
      input.receipt.installedAtMs,
    );
    const expectedAuthMethod = buildActiveAuthMethod(
      input.expectedPendingAuthMethod,
      input.receipt.installedAtMs,
    );
    if (
      authority.state !== 'active' ||
      authMethod.status !== 'active' ||
      alphabetizeStringify(authority) !== alphabetizeStringify(expectedAuthority) ||
      alphabetizeStringify(authMethod) !== alphabetizeStringify(expectedAuthMethod)
    ) {
      return null;
    }
    const session = await this.options.sessionService.getSessionV1({
      linkSessionId: input.stored.linkSessionId,
      nowMs: input.nowMs,
    });
    if (
      !session ||
      session.state.state !== 'active' ||
      session.state.authorityId !== authority.authorityId ||
      session.packageSetDigestB64u !== input.stored.packageSetDigestB64u
    ) {
      return null;
    }
    const walletSession = await this.readCommittedWalletSession(
      authority,
      authMethod,
      input.receipt.installedAtMs,
    );
    const sealedDelivery = await this.readCredentialDelivery(input.stored.linkSessionId);
    if (!sealedDelivery) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'linked-device Wallet Session credential delivery is missing after activation race',
      );
    }
    await this.assertCredentialDeliveryMatchesCommittedSession({
      stored: input.stored,
      receipt: input.receipt,
      walletSession,
      delivery: sealedDelivery,
    });
    return {
      kind: 'active',
      outcome: 'replayed',
      authority,
      authMethod,
      session,
      walletSession,
      deliveryBinding: buildLinkedDeviceWalletSessionCredentialDeliveryBindingV1(
        sealedDelivery.aad,
      ),
      sealedDelivery,
    };
  }

  async readCommittedAuthorityPackagesV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly requestedAtMs: number;
  }): Promise<CommittedAuthorityPackagesV1 | null> {
    const nowMs = requireTime(input.requestedAtMs, 'requestedAtMs');
    if (
      input.session.state.state !== 'provisioning' &&
      input.session.state.state !== 'authority_pending_local_install' &&
      input.session.state.state !== 'active'
    ) {
      throw new Error('committed authority packages are unavailable before provisioning');
    }
    const stored = await this.readInstallation(input.session.linkSessionId);
    if (!stored && input.session.state.state === 'provisioning') return null;
    if (!stored) throw new Error('committed authority packages were not found');
    await assertStoredPackageDigest(stored);
    if (stored.deviceId !== input.session.state.deviceId) {
      throw new Error('committed authority package device does not match the session');
    }
    if (
      input.session.state.state !== 'provisioning' &&
      (input.session.state.authorityId !== stored.authorityId ||
        input.session.state.packageSetDigestB64u !== stored.packageSetDigestB64u)
    ) {
      throw new Error('committed authority package identity does not match the session');
    }
    if (stored.packages.authority.createdAtMs > nowMs) {
      throw new Error('committed authority package timestamp is from the future');
    }
    return stored.packages;
  }

  async readInstalledEd25519AuthorityByIdentityV1(input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<InstalledLinkedDeviceEd25519AuthorityProjectionV1 | null> {
    try {
      const walletId = parseWalletId(input.walletId);
      const authorityId = parseWalletAuthorityId(input.authorityId);
      const walletAuthMethodId = parseWalletAuthMethodId(input.walletAuthMethodId);
      if (!walletId.ok || !authorityId.ok || !walletAuthMethodId.ok) return null;
      const stored = await this.readInstallationByAuthority(authorityId.value);
      if (
        !stored ||
        stored.walletId !== walletId.value ||
        stored.authorityId !== authorityId.value ||
        stored.authMethodId !== walletAuthMethodId.value
      ) {
        return null;
      }
      await assertStoredPackageDigest(stored);
      return projectInstalledEd25519Authority(stored);
    } catch {
      return null;
    }
  }

  async readInstalledEd25519AuthorityByMaterialActivationV1(input: {
    readonly walletId: WalletId;
    readonly materialActivation: MpcMaterialActivationRef;
  }): Promise<InstalledLinkedDeviceEd25519AuthorityProjectionV1 | null> {
    try {
      const walletId = parseWalletId(input.walletId);
      if (!walletId.ok) return null;
      const storedRows = await this.readInstallationsByWallet(walletId.value);
      for (const stored of storedRows) {
        await assertStoredPackageDigest(stored);
      }
      const candidates = storedRows.filter(
        (stored) =>
          stored.packages.signerPackages.ed25519 !== undefined &&
          mpcMaterialActivationRefsEqual(
            stored.packages.signerPackages.ed25519.materialActivation,
            input.materialActivation,
          ),
      );
      if (candidates.length !== 1) return null;
      const stored = candidates[0];
      return stored ? projectInstalledEd25519Authority(stored) : null;
    } catch {
      return null;
    }
  }

  async readInstalledEcdsaAuthorityByIdentityV1(input: {
    readonly walletId: WalletId;
    readonly authorityId: WalletAuthorityId;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<InstalledLinkedDeviceEcdsaAuthorityProjectionV1 | null> {
    try {
      const walletId = parseWalletId(input.walletId);
      const authorityId = parseWalletAuthorityId(input.authorityId);
      const walletAuthMethodId = parseWalletAuthMethodId(input.walletAuthMethodId);
      if (!walletId.ok || !authorityId.ok || !walletAuthMethodId.ok) return null;
      const stored = await this.readInstallationByAuthority(authorityId.value);
      if (
        !stored ||
        stored.walletId !== walletId.value ||
        stored.authorityId !== authorityId.value ||
        stored.authMethodId !== walletAuthMethodId.value
      ) {
        return null;
      }
      await assertStoredPackageDigest(stored);
      return projectInstalledEcdsaAuthority(stored);
    } catch {
      return null;
    }
  }

  async readInstalledEcdsaAuthorityByMaterialActivationV1(input: {
    readonly walletId: WalletId;
    readonly materialActivation: MpcMaterialActivationRef;
  }): Promise<InstalledLinkedDeviceEcdsaAuthorityProjectionV1 | null> {
    try {
      const walletId = parseWalletId(input.walletId);
      if (!walletId.ok) return null;
      const storedRows = await this.readInstallationsByWallet(walletId.value);
      for (const stored of storedRows) {
        await assertStoredPackageDigest(stored);
      }
      const candidates = storedRows.filter(
        (stored) =>
          stored.packages.signerPackages.ecdsa !== undefined &&
          mpcMaterialActivationRefsEqual(
            stored.packages.signerPackages.ecdsa.materialActivation,
            input.materialActivation,
          ),
      );
      if (candidates.length !== 1) return null;
      const stored = candidates[0];
      return stored ? projectInstalledEcdsaAuthority(stored) : null;
    } catch {
      return null;
    }
  }

  async readActivationCleanupReceiptV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceActivationCleanupReceiptV1 | null> {
    const nowMs = requireTime(input.requestedAtMs, 'requestedAtMs');
    const row = await this.readCredentialDeliveryRow(input.linkSessionId);
    if (!row) return null;
    if (row.lifecycle_kind !== 'acknowledged' && row.lifecycle_kind !== 'cleanup_complete') {
      return null;
    }
    if (row.cleanup_receipt_json === null || row.cleanup_receipt_json === undefined) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'acknowledged linked-device credential delivery has no cleanup receipt',
      );
    }
    const cleanupReceipt = parseLinkedDeviceActivationCleanupReceiptV1(
      parseD1JsonColumn(row.cleanup_receipt_json),
    );
    if (cleanupReceipt.expiresAtMs <= nowMs) return null;
    const storedAck =
      row.acknowledgement_receipt_json === null ||
      row.acknowledgement_receipt_json === undefined
        ? null
        : parseLocalAuthorityActivationFinalAckV1(
            parseD1JsonColumn(row.acknowledgement_receipt_json),
          );
    if (!storedAck) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'acknowledged linked-device credential delivery has no acknowledgement receipt',
      );
    }
    assertAcknowledgementMatchesCleanupReceipt(storedAck, cleanupReceipt);
    await assertCleanupReceiptMatchesDeliveryRow(cleanupReceipt, row);
    const installation = await this.readInstallation(input.linkSessionId);
    if (
      !installation ||
      installation.walletId !== cleanupReceipt.walletId ||
      installation.authorityId !== cleanupReceipt.authorityId ||
      installation.authMethodId !== cleanupReceipt.walletAuthMethodId ||
      installation.packageSetDigestB64u !== cleanupReceipt.packageSetDigestB64u
    ) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'activation cleanup receipt does not match the installation row',
      );
    }
    return cleanupReceipt;
  }

  async acknowledgeLocalAuthorityActivationV1(input: {
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
    readonly authentication: LocalAuthorityActivationAcknowledgementAuthenticationV1;
    readonly requestedAtMs: number;
  }): Promise<void> {
    const nowMs = requireTime(input.requestedAtMs, 'requestedAtMs');
    const acknowledgement = parseLocalAuthorityActivationFinalAckV1(input.acknowledgement);
    if (acknowledgement.acknowledgedAtMs > nowMs) {
      throw new Error('active authority acknowledgement is from the future');
    }
    if (input.authentication.kind === 'exact_wallet_session') {
      await this.assertExactAcknowledgementAuthenticationV1({
        acknowledgement,
        authentication: input.authentication,
        nowMs,
      });
    }
    const providedSession =
      input.authentication.kind === 'live' ? input.authentication.session : null;
    const session = providedSession || input.authentication.kind === 'exact_wallet_session'
      ? await this.options.sessionService.getSessionV1({
          linkSessionId: providedSession?.linkSessionId ?? acknowledgement.linkSessionId,
          nowMs,
        })
      : null;
    if (providedSession && session && session.revision !== providedSession.revision) {
      throw new Error('active authority acknowledgement session is stale');
    }
    if (!session) {
      const persistedCleanupReceipt = await this.readActivationCleanupReceiptV1({
        linkSessionId: acknowledgement.linkSessionId,
        requestedAtMs: nowMs,
      });
      if (
        input.authentication.kind === 'cleanup_receipt' &&
        (!persistedCleanupReceipt ||
          alphabetizeStringify(input.authentication.receipt) !==
            alphabetizeStringify(persistedCleanupReceipt))
      ) {
        throw new LinkedDeviceActivationIntegrityErrorV1(
          'activation cleanup receipt authentication does not match the persisted receipt',
        );
      }
      const cleanupReceipt = persistedCleanupReceipt;
      if (!cleanupReceipt) {
        if (input.authentication.kind === 'exact_wallet_session') {
          throw new LinkedDeviceActivationIntegrityErrorV1(
            'exact Wallet Session acknowledgement has no durable cleanup receipt',
          );
        }
        throw new Error('active authority acknowledgement session is stale or missing');
      }
      if (
        providedSession &&
        providedSession.qrPayload.devicePublicKeyB64u !== cleanupReceipt.devicePublicKeyB64u
      ) {
        throw new LinkedDeviceActivationIntegrityErrorV1(
          'active authority acknowledgement cleanup receipt device does not match the session',
        );
      }
      assertAcknowledgementMatchesCleanupReceipt(acknowledgement, cleanupReceipt);
      return;
    }
    if (session.state.state !== 'active') {
      throw new Error('active authority acknowledgement requires an active link session');
    }
    if (
      acknowledgement.linkSessionId !== session.linkSessionId ||
      acknowledgement.authorityId !== session.state.authorityId ||
      acknowledgement.packageSetDigestB64u !== session.packageSetDigestB64u
    ) {
      throw new Error('active authority acknowledgement identity does not match the session');
    }
    const prepared = await this.prepareActivationAcknowledgementV1({
      acknowledgement,
      session,
      nowMs,
    });
    const beforeDeleteStatements = [
      this.buildCredentialDeliveryAcknowledgementStatement(prepared),
      this.buildAuthorityAllocationDeleteStatement(acknowledgement.linkSessionId),
      this.buildCredentialDeliveryCleanupStateStatement({
        linkSessionId: acknowledgement.linkSessionId,
        from: 'pending',
        to: 'allocation_removed',
      }),
    ];
    const afterDeleteStatements = [
      this.buildCredentialDeliveryCleanupStateStatement({
        linkSessionId: acknowledgement.linkSessionId,
        from: 'allocation_removed',
        to: 'session_removed',
      }),
      this.buildCredentialDeliveryCleanupCompleteStatement(acknowledgement.linkSessionId),
    ];
    try {
      const deleted = await this.options.sessionStore.deleteActiveSessionWithStatementsV1({
        linkSessionId: session.linkSessionId,
        expectedRevision: session.revision,
        authorityId: acknowledgement.authorityId,
        packageSetDigestB64u: acknowledgement.packageSetDigestB64u,
        nowMs,
        beforeDeleteStatements,
        afterDeleteStatements,
      });
      if (
        deleted.outcome !== 'applied' &&
        deleted.outcome !== 'replayed' &&
        deleted.outcome !== 'deleted'
      ) {
        const detail = 'message' in deleted && deleted.message ? `: ${deleted.message}` : '';
        throw new Error(`active authority cleanup failed: ${deleted.outcome}${detail}`);
      }
    } catch (error: unknown) {
      const replay = await this.readActivationCleanupReceiptV1({
        linkSessionId: acknowledgement.linkSessionId,
        requestedAtMs: nowMs,
      });
      if (replay) {
        assertAcknowledgementMatchesCleanupReceipt(acknowledgement, replay);
        return;
      }
      throw error;
    }
  }

  private async assertExactAcknowledgementAuthenticationV1(input: {
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
    readonly authentication: Extract<
      LocalAuthorityActivationAcknowledgementAuthenticationV1,
      { readonly kind: 'exact_wallet_session' }
    >;
    readonly nowMs: number;
  }): Promise<void> {
    if (input.authentication.expiresAtMs <= input.nowMs) {
      throw new Error('exact Wallet Session acknowledgement authentication is expired');
    }
    const stored = await this.readInstallation(input.acknowledgement.linkSessionId);
    if (!stored) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'exact Wallet Session acknowledgement installation is missing',
      );
    }
    const expectedPrincipalId = requireParsed(
      parsePrincipalId(`linked-device:${String(stored.deviceId)}`),
      'principalId',
    );
    if (
      input.authentication.tenantId !== this.options.tenantId ||
      input.authentication.walletId !== stored.walletId ||
      input.authentication.authorityId !== stored.authorityId ||
      input.authentication.walletAuthMethodId !== stored.authMethodId ||
      input.authentication.principalId !== expectedPrincipalId ||
      input.authentication.authorizationId !== input.acknowledgement.authorizationId ||
      input.authentication.walletSessionId !== input.acknowledgement.walletSessionId
    ) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'exact Wallet Session acknowledgement identity does not match the installation',
      );
    }
    if (
      input.acknowledgement.authorityId !== stored.authorityId ||
      input.acknowledgement.packageSetDigestB64u !== stored.packageSetDigestB64u
    ) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'exact Wallet Session acknowledgement does not match the installation',
      );
    }
  }

  private async prepareActivationAcknowledgementV1(input: {
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly nowMs: number;
  }): Promise<{
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
    readonly cleanupReceipt: LinkedDeviceActivationCleanupReceiptV1;
    readonly delivery: LinkedDeviceWalletSessionCredentialDeliveryV1;
    readonly authBindingDigestB64u: DigestB64u;
    readonly authExpiresAtMs: number;
  }> {
    const stored = await this.readInstallation(input.acknowledgement.linkSessionId);
    if (!stored) throw new Error('active authority installation was not found');
    await assertStoredPackageDigest(stored);
    if (
      stored.authorityId !== input.acknowledgement.authorityId ||
      stored.packageSetDigestB64u !== input.acknowledgement.packageSetDigestB64u ||
      stored.activatedAtMs === null ||
      stored.installedRecordSetDigestB64u === null ||
      input.acknowledgement.acknowledgedAtMs < stored.activatedAtMs
    ) {
      throw new Error('active authority acknowledgement does not match the activation record');
    }
    const authority = await this.options.authorityStore.readById(stored.authorityId);
    const authMethod = await this.options.authMethodStore.readByIdV2({
      walletAuthMethodId: stored.authMethodId,
    });
    if (
      !authority ||
      authority.state !== 'active' ||
      !authMethod ||
      authMethod.status !== 'active'
    ) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'active authority acknowledgement has no active authority records',
      );
    }
    const committedWalletSession = await this.readCommittedWalletSession(
      authority,
      authMethod,
      stored.activatedAtMs,
    );
    if (
      input.acknowledgement.authorizationId !== committedWalletSession.session.authorizationId ||
      input.acknowledgement.walletSessionId !== committedWalletSession.session.walletSessionId ||
      input.acknowledgement.credentialDigestB64u !==
        committedWalletSession.primaryOperationCredentialDigestB64u
    ) {
      throw new Error('active authority acknowledgement Wallet Session identity does not match');
    }
    const receipt = buildInstallationReceiptFromStoredInstallation(stored);
    const installationReceiptDigestB64u =
      await computeWalletSessionInstallationReceiptDigestB64u(receipt);
    if (input.acknowledgement.installationReceiptDigestB64u !== installationReceiptDigestB64u) {
      throw new Error(
        'active authority acknowledgement installation receipt digest does not match the commit',
      );
    }
    const delivery = await this.readCredentialDelivery(input.acknowledgement.linkSessionId);
    if (!delivery) {
      const cleanupReceipt = await this.readActivationCleanupReceiptV1({
        linkSessionId: input.acknowledgement.linkSessionId,
        requestedAtMs: input.nowMs,
      });
      if (cleanupReceipt) {
        assertAcknowledgementMatchesCleanupReceipt(input.acknowledgement, cleanupReceipt);
        throw new LinkedDeviceActivationIntegrityErrorV1(
          'active authority acknowledgement delivery was already cleaned up',
        );
      }
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'active authority acknowledgement credential delivery is missing',
      );
    }
    await this.assertCredentialDeliveryMatchesCommittedSession({
      stored,
      receipt,
      walletSession: committedWalletSession,
      delivery,
    });
    if (delivery.aad.credentialDigestB64u !== input.acknowledgement.credentialDigestB64u) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'active authority acknowledgement credential delivery identity does not match the commit',
      );
    }
    const authExpiresAtMs = Math.min(
      input.session.qrPayload.expiresAtMs,
      delivery.aad.expiresAtMs,
      committedWalletSession.session.expiresAtMs,
    );
    if (input.acknowledgement.acknowledgedAtMs >= authExpiresAtMs) {
      throw new Error('active authority acknowledgement is expired');
    }
    const cleanupReceipt: LinkedDeviceActivationCleanupReceiptV1 = {
      kind: 'linked_device_activation_cleanup_receipt_v1',
      devicePublicKeyB64u: input.session.qrPayload.devicePublicKeyB64u,
      devicePublicKeyDigestB64u: await computeLinkedDevicePublicKeyDigestV1(
        input.session.qrPayload.devicePublicKeyB64u,
      ),
      linkSessionId: input.acknowledgement.linkSessionId,
      walletId: stored.walletId,
      authorityId: stored.authorityId,
      walletAuthMethodId: stored.authMethodId,
      packageSetDigestB64u: stored.packageSetDigestB64u,
      authorizationId: input.acknowledgement.authorizationId,
      walletSessionId: input.acknowledgement.walletSessionId,
      credentialDigestB64u: input.acknowledgement.credentialDigestB64u,
      installationReceiptDigestB64u,
      acknowledgedAtMs: input.acknowledgement.acknowledgedAtMs,
      expiresAtMs: authExpiresAtMs,
    };
    return {
      acknowledgement: input.acknowledgement,
      cleanupReceipt,
      delivery,
      authBindingDigestB64u: delivery.recipientBindingDigestB64u,
      authExpiresAtMs,
    };
  }

  private async assertCredentialDeliveryMatchesCommittedSession(input: {
    readonly stored: StoredInstallationRow;
    readonly receipt: LocalAuthorityInstallationReceiptV1;
    readonly walletSession: IssuedWalletSessionAuthorizationV2 & {
      readonly primaryOperationCredentialDigestB64u: DigestB64u;
    };
    readonly delivery: LinkedDeviceWalletSessionCredentialDeliveryV1;
  }): Promise<void> {
    const recipientPublicKey65B64u = input.stored.deliveryRecipientPublicKey65B64u;
    const session = input.walletSession.session;
    const aad = input.delivery.aad;
    const installationReceiptDigestB64u =
      await computeWalletSessionInstallationReceiptDigestB64u(input.receipt);
    if (
      !recipientPublicKey65B64u ||
      aad.namespace !== this.options.scope.namespace ||
      aad.orgId !== this.options.scope.orgId ||
      aad.projectId !== this.options.scope.projectId ||
      aad.envId !== this.options.scope.envId ||
      aad.linkSessionId !== input.stored.linkSessionId ||
      aad.tenantId !== session.tenantId ||
      aad.principalId !== session.principalId ||
      aad.walletId !== input.stored.walletId ||
      aad.authorityId !== input.stored.authorityId ||
      aad.walletAuthMethodId !== input.stored.authMethodId ||
      aad.authorizationId !== session.authorizationId ||
      aad.walletSessionId !== session.walletSessionId ||
      aad.quotaId !== input.walletSession.quota.quotaId ||
      aad.credentialDigestB64u !== input.walletSession.primaryOperationCredentialDigestB64u ||
      aad.recipientPublicKey65B64u !== recipientPublicKey65B64u ||
      aad.issuedAtMs !== session.createdAtMs ||
      aad.expiresAtMs !== session.expiresAtMs ||
      input.delivery.installationReceiptDigestB64u !== installationReceiptDigestB64u
    ) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'linked-device Wallet Session credential delivery identity is inconsistent with its commit',
      );
    }
    await assertLinkedDeviceWalletSessionCredentialDeliveryIntegrityV1(input.delivery);
  }

  private buildCredentialDeliveryAcknowledgementStatement(input: {
    readonly acknowledgement: LocalAuthorityActivationFinalAckV1;
    readonly cleanupReceipt: LinkedDeviceActivationCleanupReceiptV1;
    readonly authBindingDigestB64u: DigestB64u;
    readonly authExpiresAtMs: number;
    readonly delivery: LinkedDeviceWalletSessionCredentialDeliveryV1;
  }): D1PreparedStatementLike {
    const acknowledgementJson = JSON.stringify(input.acknowledgement);
    const cleanupReceiptJson = JSON.stringify(input.cleanupReceipt);
    const delivery = input.delivery;
    return this.options.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET lifecycle_kind = 'acknowledged', sealed_envelope_json = NULL,
                acknowledged_at_ms = ?, acknowledgement_receipt_json = ?,
                cleanup_state = 'pending', cleanup_receipt_json = ?,
                acknowledgement_auth_binding_digest_b64u = ?,
                acknowledgement_auth_package_set_digest_b64u = ?,
                acknowledgement_auth_expires_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND lifecycle_kind = 'issued'
            AND tenant_id = ? AND authorization_id = ? AND wallet_session_id = ?
            AND quota_id = ? AND principal_id = ? AND authority_id = ?
            AND wallet_id = ? AND wallet_auth_method_id = ?
            AND credential_digest_b64u = ? AND aad_digest_b64u = ?
            AND sealed_envelope_digest_b64u = ? AND installation_receipt_digest_b64u = ?`,
      )
      .bind(
        input.acknowledgement.acknowledgedAtMs,
        acknowledgementJson,
        cleanupReceiptJson,
        String(input.authBindingDigestB64u),
        String(input.acknowledgement.packageSetDigestB64u),
        input.authExpiresAtMs,
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(input.acknowledgement.linkSessionId),
        String(delivery.aad.tenantId),
        String(delivery.aad.authorizationId),
        String(delivery.aad.walletSessionId),
        String(delivery.aad.quotaId),
        String(delivery.aad.principalId),
        String(delivery.aad.authorityId),
        String(delivery.aad.walletId),
        String(delivery.aad.walletAuthMethodId),
        String(delivery.aad.credentialDigestB64u),
        String(delivery.aadDigestB64u),
        String(delivery.envelopeDigestB64u),
        String(delivery.installationReceiptDigestB64u),
      );
  }

  private buildAuthorityAllocationDeleteStatement(
    linkSessionId: LinkDeviceSessionId,
  ): D1PreparedStatementLike {
    return this.options.database
      .prepare(
        `DELETE FROM linked_device_authority_allocations
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(linkSessionId),
      );
  }

  private buildCredentialDeliveryCleanupStateStatement(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly from: 'pending' | 'allocation_removed';
    readonly to: 'allocation_removed' | 'session_removed';
  }): D1PreparedStatementLike {
    return this.options.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET cleanup_state = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND lifecycle_kind = 'acknowledged'
            AND cleanup_state = ?`,
      )
      .bind(
        input.to,
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(input.linkSessionId),
        input.from,
      );
  }

  private buildCredentialDeliveryCleanupCompleteStatement(
    linkSessionId: LinkDeviceSessionId,
  ): D1PreparedStatementLike {
    return this.options.database
      .prepare(
        `UPDATE linked_device_wallet_session_credential_deliveries_v1
            SET lifecycle_kind = 'cleanup_complete', cleanup_state = 'complete',
                cleanup_completed_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND lifecycle_kind = 'acknowledged'
            AND cleanup_state = 'session_removed'`,
      )
      .bind(
        this.nowV1(),
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(linkSessionId),
      );
  }

  private async reserveSignerMaterial(
    input: VerifiedLinkInputV1,
    sourceContributionPreparation: readonly [
      SharedOrdinarySignerMaterialReservationPreparationV1,
      ...SharedOrdinarySignerMaterialReservationPreparationV1[],
    ],
  ): Promise<{
    readonly packages: CommittedSignerPackageSetV1;
    readonly serverReservationIds: Readonly<{
      readonly ed25519?: ServerReservationRecordV1<'ed25519'>;
      readonly ecdsa_secp256k1?: ServerReservationRecordV1<'ecdsa_secp256k1'>;
    }>;
    readonly ordinarySignerMaterialPreparations: readonly [
      SharedOrdinarySignerMaterialReservationPreparationV1,
      ...SharedOrdinarySignerMaterialReservationPreparationV1[],
    ];
  }> {
    assertRecipientRequestsMatchManifest(input);
    let ed25519: OrdinaryEd25519SignerMaterialReservationV1 | undefined;
    let ecdsa: OrdinaryEcdsaSignerMaterialReservationV1 | undefined;
    let ed25519Preparation: OrdinaryEd25519SignerMaterialReservationPreparationV1 | undefined;
    let ecdsaPreparation: OrdinaryEcdsaSignerMaterialReservationPreparationV1 | undefined;
    for (const signer of input.signerManifest.signers) {
      const sourceContribution = sourceContributionForSigner(input, signer);
      const prepared = sourceContributionPreparationForSigner(
        sourceContributionPreparation,
        signer,
      );
      const targetMaterialActivation = targetMaterialActivationForPreparation(prepared);
      const sourceMaterialActivation = sourceMaterialActivationForSigner(input, signer);
      assertLinkedDeviceOrdinaryMaterialSourceContributionMatchesContextV1({
        contribution: sourceContribution,
        linkSessionId: input.linkSessionId,
        enrollmentId: input.enrollmentId,
        sourceAuthorityId: input.sourceAuthority.authority.authorityId,
        walletKeyId: signer.walletKeyId,
        targetDeviceId: input.targetDeviceId,
        targetFactorVerificationDigestB64u: input.targetFactor.verificationDigestB64u,
        sourceMaterialActivation,
        targetMaterialActivation,
        sourceSigner:
          signer.keyFamily === 'ed25519'
            ? {
                keyFamily: 'ed25519',
                walletKeyId: signer.walletKeyId,
                registeredPublicKeyB64u: signer.registeredPublicKeyB64u,
              }
            : {
                keyFamily: 'ecdsa_secp256k1',
                walletKeyId: signer.walletKeyId,
                thresholdPublicKey33B64u: signer.thresholdPublicKey33B64u,
              },
      });
      const preparation = workerReservationPreparationForContribution({
        sourceContributionPreparation: prepared,
        sourceContribution,
      });
      if (signer.keyFamily === 'ed25519') {
        if (preparation.keyFamily !== 'ed25519') {
          throw new Error('ordinary material reservation preparation family does not match signer');
        }
        const workerPreparation = preparation.preparation;
        assertPreparationActivationMatches(
          targetMaterialActivation,
          workerPreparation.sourceContribution.targetMaterialActivation,
        );
        const reservation =
          await this.options.reservationService.reserveOrdinaryInactiveSignerMaterialV1({
            kind: 'ordinary_ed25519_signer_material_reservation_request_v1',
            keyFamily: 'ed25519',
            signer,
            plannedActivationRef: targetMaterialActivation,
            preparation: workerPreparation,
          });
        if (reservation.keyFamily !== 'ed25519') {
          throw new Error('ordinary material reservation returned the wrong family');
        }
        ed25519 = reservation;
        ed25519Preparation = workerPreparation;
        continue;
      }
      if (preparation.keyFamily !== 'ecdsa_secp256k1') {
        throw new Error('ordinary material reservation preparation family does not match signer');
      }
      const workerPreparation = preparation.preparation;
      assertPreparationActivationMatches(
        targetMaterialActivation,
        workerPreparation.sourceContribution.binding.target.activation,
      );
      const reservation =
        await this.options.reservationService.reserveOrdinaryInactiveSignerMaterialV1({
          kind: 'ordinary_ecdsa_signer_material_reservation_request_v1',
          keyFamily: 'ecdsa_secp256k1',
          signer,
          plannedActivationRef: targetMaterialActivation,
          preparation: workerPreparation,
        });
      if (reservation.keyFamily !== 'ecdsa_secp256k1') {
        throw new Error('ordinary material reservation returned the wrong family');
      }
      ecdsa = reservation;
      ecdsaPreparation = workerPreparation;
    }
    if (!ed25519 && !ecdsa) throw new Error('signer manifest produced no reservations');
    if (ed25519 && ecdsa) {
      if (!ed25519Preparation || !ecdsaPreparation) {
        throw new Error('signer material reservation preparation was not retained');
      }
      return {
        packages: {
          kind: 'committed_signer_package_set_v1',
          keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
          ed25519: committedEd25519Package(ed25519),
          ecdsa: committedEcdsaPackage(ecdsa),
        },
        ordinarySignerMaterialPreparations: sourceContributionPreparation,
        serverReservationIds: {
          ed25519: {
            reservationId: ed25519.serverMaterial.reservationId,
            preparation: ed25519Preparation,
          },
          ecdsa_secp256k1: {
            reservationId: ecdsa.serverMaterial.reservationId,
            preparation: ecdsaPreparation,
          },
        },
      };
    }
    if (ed25519) {
      if (!ed25519Preparation) throw new Error('Ed25519 reservation preparation was not retained');
      return {
        packages: {
          kind: 'committed_signer_package_set_v1',
          keyFamilies: ['ed25519'],
          ed25519: committedEd25519Package(ed25519),
        },
        ordinarySignerMaterialPreparations: sourceContributionPreparation,
        serverReservationIds: {
          ed25519: {
            reservationId: ed25519.serverMaterial.reservationId,
            preparation: ed25519Preparation,
          },
        },
      };
    }
    if (!ecdsa) throw new Error('signer manifest produced no ECDSA reservation');
    if (!ecdsaPreparation) throw new Error('ECDSA reservation preparation was not retained');
    return {
      packages: {
        kind: 'committed_signer_package_set_v1',
        keyFamilies: ['ecdsa_secp256k1'],
        ecdsa: committedEcdsaPackage(ecdsa),
      },
      ordinarySignerMaterialPreparations: sourceContributionPreparation,
      serverReservationIds: {
        ecdsa_secp256k1: {
          reservationId: ecdsa.serverMaterial.reservationId,
          preparation: ecdsaPreparation,
        },
      },
    };
  }

  private async activateReservations(
    stored: StoredInstallationRow,
    activatedAtMs: number,
  ): Promise<void> {
    const activation = this.options.materialActivation;
    for (const family of stored.packages.signerPackages.keyFamilies) {
      if (family === 'ed25519') {
        const packageValue = stored.packages.signerPackages.ed25519;
        const reservation = stored.serverReservationIds.ed25519;
        if (!reservation || !packageValue)
          throw new Error('server reservation for ed25519 is missing');
        await activation.activateOrdinaryInactiveSignerMaterialV1({
          keyFamily: 'ed25519',
          reservationId: reservation.reservationId,
          materialActivation: packageValue.materialActivation,
          activatedAtMs,
          preparation: { keyFamily: 'ed25519', preparation: reservation.preparation },
        });
        continue;
      }
      const packageValue = stored.packages.signerPackages.ecdsa;
      const reservation = stored.serverReservationIds.ecdsa_secp256k1;
      if (!reservation || !packageValue) throw new Error('server reservation for ECDSA is missing');
      await activation.activateOrdinaryInactiveSignerMaterialV1({
        keyFamily: 'ecdsa_secp256k1',
        reservationId: reservation.reservationId,
        materialActivation: packageValue.materialActivation,
        activatedAtMs,
        preparation: { keyFamily: 'ecdsa_secp256k1', preparation: reservation.preparation },
      });
    }
  }

  private async readCommittedWalletSession(
    authority: ActiveWalletAuthorityV1,
    authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
    issuedAtMs: number,
  ): Promise<
    IssuedWalletSessionAuthorizationV2 & {
      readonly primaryOperationCredentialDigestB64u: DigestB64u;
    }
  > {
    const prepared = await this.options.authorizationService.prepareWalletSessionAuthorizationV2(
      this.buildWalletSessionAuthorizationInput(authority, authMethod, issuedAtMs),
    );
    const committed = await this.options.authorizationService.readWalletSessionAuthorizationV2ByMint(
      {
        tenantId: prepared.session.tenantId,
        principalId: prepared.session.principalId,
        walletId: prepared.session.walletId,
        authorityId: prepared.session.authorityId,
        walletAuthMethodId: prepared.session.walletAuthMethodId,
        mintId: prepared.session.mintId,
      },
    );
    if (!committed || committed.retiredAtMs !== null) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'linked-device Wallet Session authorization is not active',
      );
    }
    if (alphabetizeStringify(committed.session) !== alphabetizeStringify(prepared.session)) {
      throw new LinkedDeviceActivationIntegrityErrorV1(
        'linked-device Wallet Session authorization differs from its commit',
      );
    }
    return {
      session: committed.session,
      quota: prepared.quota,
      primaryOperationCredentialDigestB64u: committed.primaryOperationCredentialDigestB64u,
    };
  }

  private buildInstallationActivationStatement(input: {
    readonly stored: StoredInstallationRow;
    readonly receipt: LocalAuthorityInstallationReceiptV1;
  }): D1PreparedStatementLike {
    return this.options.database
      .prepare(
        `UPDATE linked_device_authority_installations
            SET installed_record_set_digest_b64u = ?, activated_at_ms = ?, updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND package_set_digest_b64u = ?
            AND installed_record_set_digest_b64u IS NULL AND activated_at_ms IS NULL`,
      )
      .bind(
        String(input.receipt.installedRecordSetDigestB64u),
        input.receipt.installedAtMs,
        input.receipt.installedAtMs,
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(input.stored.linkSessionId),
        String(input.stored.packageSetDigestB64u),
      );
  }

  private buildCredentialDeliveryInsertStatement(
    delivery: LinkedDeviceWalletSessionCredentialDeliveryV1,
  ): D1PreparedStatementLike {
    const aad = delivery.aad;
    return this.options.database
      .prepare(
        `INSERT INTO linked_device_wallet_session_credential_deliveries_v1 (
          namespace, org_id, project_id, env_id, link_session_id, tenant_id,
          authorization_id, wallet_session_id, quota_id, principal_id,
          authority_id, wallet_id, wallet_auth_method_id, credential_digest_b64u,
          recipient_kind, recipient_public_key_b64u, recipient_binding_digest_b64u,
          envelope_alg, aad_digest_b64u, sealed_envelope_json, sealed_envelope_digest_b64u,
          installation_receipt_digest_b64u, issued_at_ms, expires_at_ms,
          lifecycle_kind, acknowledged_at_ms, acknowledgement_receipt_json,
          cleanup_state, cleanup_receipt_json, cleanup_completed_at_ms,
          acknowledgement_auth_binding_digest_b64u,
          acknowledgement_auth_package_set_digest_b64u,
          acknowledgement_auth_expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'p256_ecdh', ?, ?,
                  'p256-ecdh-aes256gcm-v1', ?, ?, ?, ?, ?, ?, 'issued', NULL, NULL,
                  'pending', NULL, NULL, NULL, NULL, NULL)`,
      )
      .bind(
        aad.namespace,
        aad.orgId,
        aad.projectId,
        aad.envId,
        String(aad.linkSessionId),
        String(aad.tenantId),
        String(aad.authorizationId),
        String(aad.walletSessionId),
        String(aad.quotaId),
        String(aad.principalId),
        String(aad.authorityId),
        String(aad.walletId),
        String(aad.walletAuthMethodId),
        String(aad.credentialDigestB64u),
        aad.recipientPublicKey65B64u,
        String(delivery.recipientBindingDigestB64u),
        String(delivery.aadDigestB64u),
        JSON.stringify(delivery.envelope),
        String(delivery.envelopeDigestB64u),
        String(delivery.installationReceiptDigestB64u),
        aad.issuedAtMs,
        aad.expiresAtMs,
      );
  }

  private async readCredentialDelivery(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<LinkedDeviceWalletSessionCredentialDeliveryV1 | null> {
    const row = await this.readCredentialDeliveryRow(linkSessionId);
    if (!row || row.lifecycle_kind !== 'issued') return null;
    return parseStoredCredentialDelivery(row);
  }

  private async readCredentialDeliveryRow(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<Readonly<Record<string, unknown>> | null> {
    return await this.options.database
      .prepare(
        `SELECT * FROM linked_device_wallet_session_credential_deliveries_v1
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
          LIMIT 1`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(linkSessionId),
      )
      .first<Readonly<Record<string, unknown>>>();
  }

  private buildWalletSessionAuthorizationInput(
    authority: ActiveWalletAuthorityV1,
    authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
    issuedAtMs: number,
  ): IssueWalletSessionAuthorizationV2Input {
    const tenantId = requireParsed(parseTenantId(this.options.tenantId), 'tenantId');
    const principalId = requireParsed(
      parsePrincipalId(`linked-device:${String(authority.principal.deviceId)}`),
      'principalId',
    );
    const mintId = requireParsed(
      parseWalletSessionMintId(`linked-device-authority:${String(authority.authorityId)}`),
      'mintId',
    );
    const ttlMs = this.options.walletSessionTtlMs ?? 15 * 60 * 1000;
    const remainingUses = this.options.walletSessionRemainingUses ?? 100;
    if (
      !Number.isSafeInteger(ttlMs) ||
      ttlMs <= 0 ||
      !Number.isSafeInteger(remainingUses) ||
      remainingUses <= 0
    ) {
      throw new Error('ordinary Wallet Session policy is invalid');
    }
    const input: IssueWalletSessionAuthorizationV2Input = {
      tenantId,
      principalId,
      walletId: authority.walletId,
      authority,
      walletAuthMethodId: authMethod.walletAuthMethodId,
      mintId,
      remainingUses,
      issuedAtMs,
      expiresAtMs: issuedAtMs + ttlMs,
    };
    return input;
  }

  private async markInstalled(
    stored: StoredInstallationRow,
    receipt: LocalAuthorityInstallationReceiptV1,
  ): Promise<void> {
    const result = await this.options.database
      .prepare(
        `UPDATE linked_device_authority_installations
            SET installed_record_set_digest_b64u = ?, activated_at_ms = ?, updated_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND package_set_digest_b64u = ?
            AND (installed_record_set_digest_b64u IS NULL OR installed_record_set_digest_b64u = ?)`,
      )
      .bind(
        String(receipt.installedRecordSetDigestB64u),
        receipt.installedAtMs,
        receipt.installedAtMs,
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(stored.linkSessionId),
        String(stored.packageSetDigestB64u),
        String(receipt.installedRecordSetDigestB64u),
      )
      .run();
    if (d1ChangedRows(result) !== 1) {
      const replay = await this.readInstallation(stored.linkSessionId);
      if (replay?.installedRecordSetDigestB64u !== receipt.installedRecordSetDigestB64u) {
        throw new Error('installation acknowledgement conflicts with a prior receipt');
      }
    }
  }

  private async prepareAuthorityAllocation(
    input: CommitPendingAuthorityInputV1,
    existing: StoredInstallationRow | null,
  ): Promise<AuthorityAllocationPreparation> {
    const current = await this.readAuthorityAllocation(input.linkSessionId);
    if (current) {
      assertAuthorityAllocationMatches(current, input, existing);
      return { authorityId: current.authorityId, statement: null };
    }
    const candidate =
      existing?.authorityId ??
      requireParsed(
        parseWalletAuthorityId(
          `wallet-authority:${secureRandomBase64Url(32, 'linked-device wallet authority id')}`,
        ),
        'authorityId',
      );
    const statement = this.options.database
      .prepare(
        `INSERT INTO linked_device_authority_allocations (
          namespace, org_id, project_id, env_id, link_session_id,
          authority_id, wallet_id, enrollment_id, device_id, created_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(input.linkSessionId),
        String(candidate),
        String(input.walletId),
        String(input.enrollmentId),
        String(input.targetDeviceId),
        input.nowMs,
      );
    return { authorityId: candidate, statement };
  }

  private async prepareEmailOtpEnrollmentStatements(
    input: CommitPendingAuthorityInputV1,
  ): Promise<readonly D1PreparedStatementLike[]> {
    if (input.targetFactor.kind !== 'verified_email_otp_target_v1') return [];
    if (input.targetFactor.enrollment.kind !== 'new_enrollment') return [];
    const material = input.emailOtpEnrollment;
    if (!material) {
      throw new Error('new Email OTP target is missing enrollment material');
    }
    const finalizer = this.options.emailOtpEnrollmentFinalizer;
    if (!finalizer) {
      throw new Error('new Email OTP target enrollment finalizer is not configured');
    }
    const prepared = await finalizer.prepareLinkedDeviceEnrollment({
      walletId: String(input.walletId),
      orgId: this.options.scope.orgId,
      authSubjectId: input.targetFactor.providerUserId,
      verifiedEmail: input.targetFactor.targetEmail,
      material,
      nowMs: input.nowMs,
    });
    if (!prepared.ok) throw new Error(prepared.message);
    return prepared.statements;
  }

  private async readAuthorityAllocation(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<AuthorityAllocation | null> {
    const row = await this.options.database
      .prepare(
        `SELECT authority_id, wallet_id, enrollment_id, device_id
           FROM linked_device_authority_allocations
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
          LIMIT 1`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(linkSessionId),
      )
      .first<Readonly<Record<string, unknown>>>();
    if (!row) return null;
    return parseAuthorityAllocation(row);
  }

  private async buildInstallationInsertStatement(input: {
    readonly input: CommitPendingAuthorityInputV1;
    readonly packages: CommittedAuthorityPackagesV1;
    readonly serverReservationIds: Readonly<{
      readonly ed25519?: ServerReservationRecordV1<'ed25519'>;
      readonly ecdsa_secp256k1?: ServerReservationRecordV1<'ecdsa_secp256k1'>;
    }>;
    readonly nowMs: number;
  }): Promise<D1PreparedStatementLike> {
    return this.options.database
      .prepare(
        `INSERT INTO linked_device_authority_installations (
          namespace, org_id, project_id, env_id, link_session_id, authority_id,
          wallet_id, auth_method_id, device_id, package_set_digest_b64u,
          target_factor_verification_digest_b64u, target_factor_verified_at_ms,
          source_manifest_digest_b64u, delivery_recipient_public_key_b64u, packages_json,
          server_reservation_ids_json, installed_record_set_digest_b64u,
          activated_at_ms, created_at_ms, updated_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(input.input.linkSessionId),
        String(input.packages.authority.authorityId),
        String(input.packages.authority.walletId),
        String(input.packages.authMethod.walletAuthMethodId),
        String(input.input.targetDeviceId),
        String(input.packages.packageSetDigestB64u),
        String(input.input.targetFactor.verificationDigestB64u),
        input.input.targetFactor.verifiedAtMs,
        await digestJson(input.input.signerManifest),
        input.input.deliveryRecipientPublicKey65B64u,
        JSON.stringify(input.packages),
        JSON.stringify({
          ed25519: input.serverReservationIds.ed25519 ?? null,
          ecdsa_secp256k1: input.serverReservationIds.ecdsa_secp256k1 ?? null,
        }),
        null,
        null,
        input.nowMs,
        input.nowMs,
      );
  }

  private async readInstallation(
    linkSessionId: LinkDeviceSessionId,
  ): Promise<StoredInstallationRow | null> {
    const row = await this.options.database
      .prepare(
        `SELECT * FROM linked_device_authority_installations
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? LIMIT 1`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(linkSessionId),
      )
      .first<Readonly<Record<string, unknown>>>();
    return row ? parseStoredInstallationRow(row) : null;
  }

  private async readInstallationByAuthority(
    authorityId: WalletAuthorityId,
  ): Promise<StoredInstallationRow | null> {
    const row = await this.options.database
      .prepare(
        `SELECT * FROM linked_device_authority_installations
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND authority_id = ? LIMIT 1`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(authorityId),
      )
      .first<Readonly<Record<string, unknown>>>();
    return row ? parseStoredInstallationRow(row) : null;
  }

  private async readInstallationsByWallet(
    walletId: WalletId,
  ): Promise<readonly StoredInstallationRow[]> {
    const rows = await this.options.database
      .prepare(
        `SELECT * FROM linked_device_authority_installations
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND wallet_id = ?
          ORDER BY link_session_id ASC`,
      )
      .bind(
        this.options.scope.namespace,
        this.options.scope.orgId,
        this.options.scope.projectId,
        this.options.scope.envId,
        String(walletId),
      )
      .all<Readonly<Record<string, unknown>>>();
    return (rows.results ?? []).map(parseStoredInstallationRow);
  }
}

function assertRecipientRequestsMatchManifest(input: VerifiedLinkInputV1): void {
  if (
    input.ordinarySignerMaterialRecipientRequests.length !== input.signerManifest.signers.length
  ) {
    throw new Error('ordinary signer material recipient requests do not match the signer manifest');
  }
  if (input.sourceContribution.length !== input.signerManifest.signers.length) {
    throw new Error('ordinary source contributions do not match the signer manifest');
  }
  for (const signer of input.signerManifest.signers) {
    recipientRequestForSigner(input, signer);
    sourceContributionForSigner(input, signer);
  }
}

function recipientRequestForSigner(
  input: VerifiedLinkInputV1,
  signer: ExactSigner,
): OrdinarySignerMaterialRecipientRequestV1 {
  const matches = input.ordinarySignerMaterialRecipientRequests.filter(
    (request) =>
      request.walletKeyId === signer.walletKeyId && request.keyFamily === signer.keyFamily,
  );
  if (matches.length !== 1) {
    throw new Error(
      `ordinary signer material recipient request for ${String(signer.walletKeyId)} is missing or duplicated`,
    );
  }
  const request = matches[0];
  if (!request) throw new Error('ordinary signer material recipient request is missing');
  return request;
}

function sourceContributionForSigner(
  input: VerifiedLinkInputV1,
  signer: ExactSigner,
): LinkedDeviceOrdinaryMaterialSourceContributionV1 {
  const matches = input.sourceContribution.filter(
    (contribution) =>
      contribution.walletKeyId === signer.walletKeyId &&
      contribution.keyFamily === signer.keyFamily,
  );
  if (matches.length !== 1) {
    throw new Error(
      `ordinary source contribution for ${String(signer.walletKeyId)} is missing or duplicated`,
    );
  }
  const contribution = matches[0];
  if (!contribution) throw new Error('ordinary source contribution is missing');
  return contribution;
}

function sourceMaterialActivationForSigner(
  input: VerifiedLinkInputV1,
  signer: ExactSigner,
): MpcMaterialActivationRef {
  const activation =
    signer.keyFamily === 'ed25519'
      ? input.sourceAuthority.authority.signerActivations.ed25519?.materialActivation
      : input.sourceAuthority.authority.signerActivations.ecdsa?.materialActivation;
  if (!activation) {
    throw new Error(`ordinary source activation for ${String(signer.walletKeyId)} is missing`);
  }
  return activation;
}

function sourceContributionPreparationForSigner(
  preparations: readonly [
    SharedOrdinarySignerMaterialReservationPreparationV1,
    ...SharedOrdinarySignerMaterialReservationPreparationV1[],
  ],
  signer: ExactSigner,
): SharedOrdinarySignerMaterialReservationPreparationV1 {
  const preparation = preparations.find((candidate) =>
    signer.keyFamily === 'ed25519' ? 'kind' in candidate : !('kind' in candidate),
  );
  if (!preparation) {
    throw new Error(`source contribution preparation for ${signer.keyFamily} is missing`);
  }
  return preparation;
}

function workerReservationPreparationForContribution(input: {
  readonly sourceContributionPreparation: SharedOrdinarySignerMaterialReservationPreparationV1;
  readonly sourceContribution: LinkedDeviceOrdinaryMaterialSourceContributionV1;
}): WorkerOrdinarySignerMaterialReservationPreparationV1 {
  if ('kind' in input.sourceContributionPreparation) {
    if (input.sourceContribution.keyFamily !== 'ed25519') {
      throw new Error('Ed25519 source contribution preparation family does not match contribution');
    }
    return {
      keyFamily: 'ed25519',
      preparation: {
        kind: 'ordinary_ed25519_signer_material_reservation_preparation_v1',
        sourceContribution: input.sourceContribution,
        targetBinding: input.sourceContributionPreparation.targetAdmission.binding,
        applicationBinding: input.sourceContributionPreparation.applicationBinding,
      },
    };
  }
  if (input.sourceContribution.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA source contribution preparation family does not match contribution');
  }
  return {
    keyFamily: 'ecdsa_secp256k1',
    preparation: {
      kind: 'ordinary_ecdsa_signer_material_reservation_preparation_v1',
      sourceDerivation: input.sourceContribution.sourceDerivation,
      sourceContribution: input.sourceContribution.package,
    },
  };
}

function targetMaterialActivationForPreparation(
  preparation: SharedOrdinarySignerMaterialReservationPreparationV1,
): MpcMaterialActivationRef {
  return 'kind' in preparation
    ? preparation.targetMaterialActivation
    : preparation.target.activation;
}

async function validateVerifiedLinkInput(
  input: VerifiedLinkInputV1,
  nowMs: number,
  authMethodStore: Pick<D1WalletAuthMethodStore, 'readByIdV2'>,
  sourceContributionPreparation: readonly [
    SharedOrdinarySignerMaterialReservationPreparationV1,
    ...SharedOrdinarySignerMaterialReservationPreparationV1[],
  ],
): Promise<void> {
  if (input.sourceAuthority.authority.state !== 'active')
    throw new Error('source authority must be active');
  if (input.sourceAuthority.authority.walletId !== input.walletId)
    throw new Error('source authority wallet does not match link wallet');
  if (
    input.sourceAuthority.authority.authorityDigestB64u !==
    input.sourceAuthority.authorityDigestB64u
  )
    throw new Error('source authority digest is unverified');
  if (!(await walletAuthorityDigestsMatchV1(input.sourceAuthority.authority)))
    throw new Error('source authority digest does not match its canonical record');
  const sourceAuthMethod = await authMethodStore.readByIdV2({
    walletAuthMethodId: input.sourceAuthority.authMethodId,
  });
  if (
    !sourceAuthMethod ||
    sourceAuthMethod.status !== 'active' ||
    sourceAuthMethod.walletId !== input.walletId ||
    sourceAuthMethod.walletAuthorityId !== input.sourceAuthority.authority.authorityId
  ) {
    throw new Error('source auth method is not active for the verified authority');
  }
  if (
    input.sourceAuthority.verifiedRevocationEpoch !==
    input.sourceAuthority.authority.revocationEpoch
  )
    throw new Error('source authority revocation epoch is stale');
  if (input.sourceAuthority.verifiedAtMs > nowMs || input.targetFactor.verifiedAtMs > nowMs)
    throw new Error('link verification is from the future');
  if (input.targetFactor.authMethod.walletId !== input.walletId)
    throw new Error('target auth method wallet does not match link wallet');
  if (input.targetFactor.kind === 'verified_email_otp_target_v1') {
    if (
      input.targetFactor.enrollment.kind === 'new_enrollment'
        ? input.emailOtpEnrollment === null
        : input.emailOtpEnrollment !== null
    ) {
      throw new Error('Email OTP target enrollment material does not match its branch');
    }
  } else if (input.emailOtpEnrollment !== null) {
    throw new Error('Passkey target cannot carry Email OTP enrollment material');
  }
  if (input.signerManifest.signers.some((signer) => signer.walletId !== input.walletId))
    throw new Error('signer manifest wallet does not match link wallet');
  assertRecipientRequestsMatchManifest(input);
  const permissions = parseDelegatedWalletPermissionSetV1(input.permissions);
  if (!permissions.ok) throw new Error(permissions.error.message);
  const attenuation = validateDelegatedWalletAuthorityAttenuationV1({
    parent: buildDelegatedWalletAuthorityV1({
      permissions: input.sourceAuthority.authority.permissions,
    }),
    child: buildDelegatedWalletAuthorityV1({ permissions: permissions.value }),
  });
  if (!attenuation.ok) throw new Error(attenuation.error.message);
  if (!input.sourceAuthority.authority.permissions.includes('link_devices'))
    throw new Error('source authority cannot link devices');
  if (
    !Number.isSafeInteger(input.sourceAuthority.authority.revocationEpoch) ||
    input.sourceAuthority.authority.revocationEpoch < 0
  )
    throw new Error('source authority revocation epoch is invalid');
  assertSourceContributionPreparationsMatchInputV1(input, sourceContributionPreparation);
}

function requireSourceContributionPreparations(
  session: LinkedDeviceSessionRecordV1,
): readonly [
  SharedOrdinarySignerMaterialReservationPreparationV1,
  ...SharedOrdinarySignerMaterialReservationPreparationV1[],
] {
  const preparations = session.sourceContributionPreparation;
  if (!preparations) {
    throw new Error('linked-device source contribution preparations are missing from the session');
  }
  return preparations;
}

function assertSourceContributionPreparationsMatchInputV1(
  input: VerifiedLinkInputV1,
  preparations: readonly [
    SharedOrdinarySignerMaterialReservationPreparationV1,
    ...SharedOrdinarySignerMaterialReservationPreparationV1[],
  ],
): void {
  if (
    input.sourceContribution.length !== input.signerManifest.signers.length ||
    preparations.length !== input.signerManifest.signers.length ||
    input.ordinarySignerMaterialRecipientRequests.length !== input.signerManifest.signers.length
  ) {
    throw new Error('linked-device source contributions do not match the signer manifest');
  }
  for (let index = 0; index < input.signerManifest.signers.length; index += 1) {
    const signer = input.signerManifest.signers[index];
    const contribution = input.sourceContribution[index];
    const preparation = preparations[index];
    const request = input.ordinarySignerMaterialRecipientRequests[index];
    if (!signer || !contribution || !preparation || !request) {
      throw new Error(`linked-device source contribution ${index} is incomplete`);
    }
    if (
      signer.keyFamily !== contribution.keyFamily ||
      signer.keyFamily !== request.keyFamily ||
      signer.walletKeyId !== request.walletKeyId
    ) {
      throw new Error(
        `linked-device source contribution ${index} family differs from the manifest`,
      );
    }
    const targetMaterialActivation = targetMaterialActivationForPreparation(preparation);
    assertLinkedDeviceOrdinaryMaterialSourceContributionMatchesContextV1({
      contribution,
      linkSessionId: input.linkSessionId,
      enrollmentId: input.enrollmentId,
      sourceAuthorityId: input.sourceAuthority.authority.authorityId,
      walletKeyId: signer.walletKeyId,
      targetDeviceId: input.targetDeviceId,
      targetFactorVerificationDigestB64u: input.targetFactor.verificationDigestB64u,
      sourceMaterialActivation: sourceMaterialActivationForSigner(input, signer),
      targetMaterialActivation,
      sourceSigner:
        signer.keyFamily === 'ed25519'
          ? {
              keyFamily: 'ed25519',
              walletKeyId: signer.walletKeyId,
              registeredPublicKeyB64u: signer.registeredPublicKeyB64u,
            }
          : {
              keyFamily: 'ecdsa_secp256k1',
              walletKeyId: signer.walletKeyId,
              thresholdPublicKey33B64u: signer.thresholdPublicKey33B64u,
            },
    });
    assertPreparationMatchesContributionV1(preparation, contribution, request);
  }
}

function assertPreparationMatchesContributionV1(
  preparation: SharedOrdinarySignerMaterialReservationPreparationV1,
  contribution: LinkedDeviceOrdinaryMaterialSourceContributionV1,
  request: OrdinarySignerMaterialRecipientRequestV1,
): void {
  if ('kind' in preparation) {
    if (
      contribution.keyFamily !== 'ed25519' ||
      preparation.sourceRegisteredPublicKeyB64u !== contribution.sourceRegisteredPublicKeyB64u ||
      !mpcMaterialActivationRefsEqual(
        preparation.targetMaterialActivation,
        contribution.targetMaterialActivation,
      ) ||
      preparation.targetClientRecipientPublicKeyB64u !==
        contribution.targetClientRecipientPublicKeyB64u ||
      preparation.targetSigningWorkerRecipientPublicKeyB64u !==
        contribution.targetSigningWorkerRecipientPublicKeyB64u ||
      alphabetizeStringify(preparation.sourceBinding) !==
        alphabetizeStringify(contribution.sourceBinding) ||
      !('recipientPublicKeyB64u' in request) ||
      request.recipientPublicKeyB64u !== preparation.targetClientRecipientPublicKeyB64u
    ) {
      throw new Error('Ed25519 source contribution differs from its persisted preparation');
    }
    return;
  }
  if (
    contribution.keyFamily !== 'ecdsa_secp256k1' ||
    !mpcMaterialActivationRefsEqual(
      preparation.source.activation,
      contribution.sourceSigner.activation,
    ) ||
    !mpcMaterialActivationRefsEqual(
      preparation.target.activation,
      contribution.target.activation,
    ) ||
    preparation.source.thresholdPublicKey33B64u !==
      contribution.sourceSigner.thresholdPublicKey33B64u ||
    preparation.target.clientRecipientPublicKeyB64u !==
      contribution.target.clientRecipientPublicKeyB64u ||
    preparation.target.signingWorkerRecipientPublicKeyB64u !==
      contribution.target.signingWorkerRecipientPublicKeyB64u ||
    !('clientEphemeralPublicKey' in request) ||
    linkedDeviceX25519RecipientPublicKeyB64uV1(request.clientEphemeralPublicKey) !==
      preparation.target.clientRecipientPublicKeyB64u
  ) {
    throw new Error('ECDSA source contribution differs from its persisted preparation');
  }
}

function assertPreparationActivationMatches(
  expected: MpcMaterialActivationRef,
  actual: MpcMaterialActivationRef,
): void {
  if (!mpcMaterialActivationRefsEqual(expected, actual)) {
    throw new Error(
      'ordinary material preparation activation differs from the persisted target activation',
    );
  }
}

async function buildPendingAuthority(input: {
  readonly authorityId: WalletAuthorityId;
  readonly input: VerifiedLinkInputV1;
  readonly activationSet: WalletSignerActivationSetV1;
  readonly packageSetDigestB64u: DigestB64u;
  readonly nowMs: number;
}): Promise<PendingWalletAuthorityV1> {
  const activationDigest = await computeWalletSignerActivationSetDigestB64u(input.activationSet);
  const draft: PendingWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId: input.authorityId,
    walletId: input.input.walletId,
    principal: { kind: 'owner_device', deviceId: input.input.targetDeviceId },
    provenance: {
      kind: 'device_link',
      enrollmentId: input.input.enrollmentId,
      sourceAuthorityId: input.input.sourceAuthority.authority.authorityId,
      linkSessionId: input.input.linkSessionId,
    },
    permissions: input.input.permissions,
    signerActivations: input.activationSet,
    signerActivationSetDigestB64u: activationDigest,
    authorityDigestB64u: input.packageSetDigestB64u,
    revocationEpoch: 0,
    createdAtMs: input.nowMs,
    updatedAtMs: input.nowMs,
    state: 'pending_local_install',
    localInstallPackageSetDigestB64u: input.packageSetDigestB64u,
  };
  const authorityDigestB64u = await computeWalletAuthorityDigestB64u(draft);
  return buildPendingWalletAuthorityV1({ ...draft, authorityDigestB64u });
}

function buildPendingAuthMethod(
  input: VerifiedLinkInputV1,
  authorityId: WalletAuthorityId,
  nowMs: number,
): CommittedAuthorityPackagesV1['authMethod'] {
  const draft = input.targetFactor.authMethod;
  if (draft.createdAtMs > nowMs) throw new Error('target auth method is from the future');
  if (draft.kind === 'passkey') {
    const record = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: draft.walletAuthMethodId,
      walletId: draft.walletId,
      walletAuthorityId: authorityId,
      kind: 'passkey',
      status: 'pending_local_install',
      rpId: draft.rpId,
      credentialIdB64u: draft.credentialIdB64u,
      credentialPublicKeyB64u: draft.credentialPublicKeyB64u,
      counter: draft.counter,
      createdAtMs: draft.createdAtMs,
      updatedAtMs: nowMs,
    });
    if (record.status !== 'pending_local_install')
      throw new Error('auth method builder returned a non-pending record');
    return record;
  }
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: draft.walletAuthMethodId,
    walletId: draft.walletId,
    walletAuthorityId: authorityId,
    kind: 'email_otp',
    status: 'pending_local_install',
    emailHashHex: draft.emailHashHex,
    registrationAuthorityId: draft.registrationAuthorityId,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: nowMs,
  });
  if (record.status !== 'pending_local_install')
    throw new Error('auth method builder returned a non-pending record');
  return record;
}

function buildActivationSet(
  manifest: VerifiedLinkInputV1['signerManifest'],
  reservations: {
    readonly packages: CommittedSignerPackageSetV1;
  },
): WalletSignerActivationSetV1 {
  const ed25519 = reservations.packages.ed25519;
  const ecdsa = reservations.packages.ecdsa;
  if (ed25519 && ecdsa) {
    return buildWalletSignerActivationSetV1({
      manifest,
      materialActivations: {
        keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
        ed25519: ed25519.materialActivation,
        ecdsa: ecdsa.materialActivation,
      },
    });
  }
  if (ed25519) {
    return buildWalletSignerActivationSetV1({
      manifest,
      materialActivations: {
        keyFamilies: ['ed25519'],
        ed25519: ed25519.materialActivation,
      },
    });
  }
  if (!ecdsa) throw new Error('committed signer packages are empty');
  return buildWalletSignerActivationSetV1({
    manifest,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: ecdsa.materialActivation,
    },
  });
}

function committedEd25519Package(
  reservation: OrdinaryEd25519SignerMaterialReservationV1,
): CommittedEd25519SignerPackageV1 {
  return {
    kind: 'committed_ed25519_signer_package_v1',
    materialActivation: reservation.materialActivation,
    targetBinding: reservation.targetBinding,
    applicationBinding: reservation.applicationBinding,
    participantIds: reservation.participantIds,
    activationReceipt: reservation.activationReceipt,
    deriver_a_client_package: reservation.clientMaterial.deriver_a_client_package,
    deriver_b_client_package: reservation.clientMaterial.deriver_b_client_package,
  };
}

function committedEcdsaPackage(
  reservation: OrdinaryEcdsaSignerMaterialReservationV1,
): CommittedEcdsaSignerPackageV1 {
  return {
    kind: 'committed_ecdsa_signer_package_v1',
    materialActivation: reservation.materialActivation,
    encryptedTargetClientShare: reservation.clientMaterial.encryptedTargetClientShare,
    activationReceipt: reservation.activationReceipt,
  };
}

async function buildActiveAuthority(
  pending: PendingWalletAuthorityV1,
  activatedAtMs: number,
): Promise<ActiveWalletAuthorityV1> {
  const draft: ActiveWalletAuthorityV1 = {
    kind: 'wallet_authority_v1',
    authorityId: pending.authorityId,
    walletId: pending.walletId,
    principal: pending.principal,
    provenance: pending.provenance,
    permissions: pending.permissions,
    signerActivations: pending.signerActivations,
    signerActivationSetDigestB64u: pending.signerActivationSetDigestB64u,
    authorityDigestB64u: pending.authorityDigestB64u,
    revocationEpoch: pending.revocationEpoch,
    createdAtMs: pending.createdAtMs,
    updatedAtMs: activatedAtMs,
    state: 'active',
    activatedAtMs,
  };
  return buildActiveWalletAuthorityV1({
    ...draft,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(draft),
  });
}

function buildActiveAuthMethod(
  pending: CommittedAuthorityPackagesV1['authMethod'],
  activatedAtMs: number,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  if (pending.kind === 'passkey') {
    const record = buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: pending.walletAuthMethodId,
      walletId: pending.walletId,
      walletAuthorityId: pending.walletAuthorityId,
      kind: 'passkey',
      status: 'active',
      rpId: pending.rpId,
      credentialIdB64u: pending.credentialIdB64u,
      credentialPublicKeyB64u: pending.credentialPublicKeyB64u,
      counter: pending.counter,
      createdAtMs: pending.createdAtMs,
      updatedAtMs: activatedAtMs,
      activatedAtMs,
    });
    if (record.status !== 'active')
      throw new Error('auth method builder returned a non-active record');
    return record;
  }
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: pending.walletAuthMethodId,
    walletId: pending.walletId,
    walletAuthorityId: pending.walletAuthorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: pending.emailHashHex,
    registrationAuthorityId: pending.registrationAuthorityId,
    createdAtMs: pending.createdAtMs,
    updatedAtMs: activatedAtMs,
    activatedAtMs,
  });
  if (record.status !== 'active')
    throw new Error('auth method builder returned a non-active record');
  return record;
}

async function buildPasskeyCredentialPromotionStatements(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletAuthorityStoreScope;
  readonly listWalletEd25519Signers: ListWalletEd25519SignersV1;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly activatedAtMs: number;
}): Promise<readonly D1PreparedStatementLike[]> {
  if (input.authMethod.kind !== 'passkey') return [];
  const signer = await resolveLinkedDeviceEd25519Signer({
    authority: input.authority,
    listWalletEd25519Signers: input.listWalletEd25519Signers,
  });
  const bindingBase = {
    version: 'webauthn_credential_binding_v1',
    rpId: input.authMethod.rpId,
    credentialIdB64u: input.authMethod.credentialIdB64u,
    userId: input.authMethod.walletId,
    createdAtMs: input.authMethod.createdAtMs,
    updatedAtMs: input.activatedAtMs,
  } as const;
  const binding: WebAuthnCredentialBindingRecord = signer
    ? {
        ...bindingBase,
        nearAccountId: signer.nearAccountId,
        nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
        signerSlot: signer.signerSlot,
        publicKey: signer.publicKey,
        relayerKeyId: signer.signingWorkerId,
        keyVersion: signer.keyVersion,
        recoveryExportCapable: signer.recoveryExportCapable,
        clientParticipantId: signer.participantIds[0],
        relayerParticipantId: signer.participantIds[1],
        participantIds: [...signer.participantIds],
        runtimePolicyScope: signer.runtimePolicyScope,
      }
    : bindingBase;
  return [
    prepareD1WebAuthnAuthenticatorInsertStatement({
      database: input.database,
      scope: input.scope,
      userId: input.authMethod.walletId,
      record: {
        credentialIdB64u: input.authMethod.credentialIdB64u,
        credentialPublicKeyB64u: input.authMethod.credentialPublicKeyB64u,
        counter: input.authMethod.counter,
        createdAtMs: input.authMethod.createdAtMs,
        updatedAtMs: input.activatedAtMs,
        deviceInfo: unknownWebAuthnAuthenticatorDeviceInfo(),
      },
    }),
    prepareD1WebAuthnCredentialBindingInsertStatement({
      database: input.database,
      scope: input.scope,
      record: binding,
    }),
  ];
}

async function resolveLinkedDeviceEd25519Signer(input: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly listWalletEd25519Signers: ListWalletEd25519SignersV1;
}): Promise<WalletEd25519SignerRecord | null> {
  const activation = input.authority.signerActivations.ed25519;
  if (!activation) return null;
  const signers = await input.listWalletEd25519Signers(input.authority.walletId);
  const matches = signers.filter((signer) =>
    linkedDeviceEd25519SignerMatchesAuthority(signer, activation.signer),
  );
  if (matches.length === 0) {
    throw new Error('linked authority Ed25519 signer record is missing');
  }
  if (matches.length > 1) {
    throw new Error('linked authority Ed25519 signer record is ambiguous');
  }
  const signer = matches[0];
  if (!signer) throw new Error('linked authority Ed25519 signer record is missing');
  return signer;
}

function linkedDeviceEd25519SignerMatchesAuthority(
  signer: WalletEd25519SignerRecord,
  authoritySigner: Extract<ExactSigner, { readonly keyFamily: 'ed25519' }>,
): boolean {
  const walletKeyId = parseWalletKeyId(
    `wallet-key:ed25519:${signer.walletId}:${signer.nearEd25519SigningKeyId}`,
  );
  if (!walletKeyId.ok) return false;
  return (
    signer.walletId === authoritySigner.walletId &&
    walletKeyId.value === authoritySigner.walletKeyId &&
    authoritySigner.registeredPublicKeyB64u ===
      base64UrlEncode(
        Uint8Array.from(
          signer.activeYaoCapability.activationResult.public_receipt.registered_public_key,
        ),
      )
  );
}

function projectInstalledEd25519Authority(
  stored: StoredInstallationRow,
): InstalledLinkedDeviceEd25519AuthorityProjectionV1 | null {
  if (stored.activatedAtMs === null || stored.installedRecordSetDigestB64u === null) return null;
  const packages = stored.packages;
  if (
    packages.authority.authorityId !== stored.authorityId ||
    packages.authority.walletId !== stored.walletId ||
    packages.authMethod.walletAuthMethodId !== stored.authMethodId ||
    packages.authMethod.walletId !== stored.walletId ||
    packages.authMethod.walletAuthorityId !== stored.authorityId ||
    packages.authority.provenance.kind !== 'device_link' ||
    packages.authority.provenance.linkSessionId !== stored.linkSessionId ||
    packages.authority.principal.deviceId !== stored.deviceId
  ) {
    return null;
  }
  const signerPackage = packages.signerPackages.ed25519;
  const authorityActivation = packages.authority.signerActivations.ed25519;
  if (!signerPackage || !authorityActivation) {
    return null;
  }
  if (
    !mpcMaterialActivationRefsEqual(
      signerPackage.materialActivation,
      authorityActivation.materialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(
      signerPackage.materialActivation,
      routerAbMpcMaterialActivationRefFromWire(signerPackage.targetBinding.material_activation),
    ) ||
    !mpcMaterialActivationRefsEqual(
      signerPackage.materialActivation,
      routerAbMpcMaterialActivationRefFromWire(signerPackage.activationReceipt.material_activation),
    )
  ) {
    return null;
  }
  if (
    signerPackage.targetBinding.operation !== 'registration' ||
    signerPackage.applicationBinding.wallet_id !== String(stored.walletId) ||
    base64UrlEncode(Uint8Array.from(signerPackage.activationReceipt.registered_public_key)) !==
      String(authorityActivation.signer.registeredPublicKeyB64u)
  ) {
    return null;
  }
  return {
    walletId: stored.walletId,
    authorityId: stored.authorityId,
    walletAuthMethodId: stored.authMethodId,
    linkSessionId: stored.linkSessionId,
    deviceId: stored.deviceId,
    materialActivation: signerPackage.materialActivation,
    targetBinding: signerPackage.targetBinding,
    targetSessionId: signerPackage.targetBinding.lifecycle.session_id,
    applicationBinding: signerPackage.applicationBinding,
    participantIds: signerPackage.participantIds,
    activationReceipt: signerPackage.activationReceipt,
    installedRecordSetDigestB64u: stored.installedRecordSetDigestB64u,
    activatedAtMs: stored.activatedAtMs,
  };
}

function projectInstalledEcdsaAuthority(
  stored: StoredInstallationRow,
): InstalledLinkedDeviceEcdsaAuthorityProjectionV1 | null {
  if (stored.activatedAtMs === null || stored.installedRecordSetDigestB64u === null) return null;
  const packages = stored.packages;
  if (
    packages.authority.authorityId !== stored.authorityId ||
    packages.authority.walletId !== stored.walletId ||
    packages.authMethod.walletAuthMethodId !== stored.authMethodId ||
    packages.authMethod.walletId !== stored.walletId ||
    packages.authMethod.walletAuthorityId !== stored.authorityId ||
    packages.authority.provenance.kind !== 'device_link' ||
    packages.authority.provenance.linkSessionId !== stored.linkSessionId ||
    packages.authority.principal.deviceId !== stored.deviceId
  ) {
    return null;
  }
  const signerPackage = packages.signerPackages.ecdsa;
  const authorityActivation = packages.authority.signerActivations.ecdsa;
  if (!signerPackage || !authorityActivation) return null;

  const receipt = signerPackage.activationReceipt;
  const source = receipt.binding.source;
  const target = receipt.binding.target;
  const sourceScope = receipt.sourceDerivation.sourceNormalSigning.scope;
  const targetScope = receipt.normalSigning.scope;
  const authorityEthereumAddress = ecdsaAuthorityEvmAddressB64u(
    authorityActivation.signer.evmAddress,
  );
  if (
    authorityEthereumAddress === null ||
    !mpcMaterialActivationRefsEqual(
      signerPackage.materialActivation,
      authorityActivation.materialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(signerPackage.materialActivation, target.activation) ||
    !mpcMaterialActivationRefsEqual(
      signerPackage.materialActivation,
      routerAbMpcMaterialActivationRefFromWire(targetScope.material_activation),
    ) ||
    String(receipt.binding.linkSessionId) !== String(stored.linkSessionId) ||
    String(receipt.binding.enrollmentId) !== String(packages.authority.provenance.enrollmentId) ||
    String(receipt.binding.sourceAuthorityId) !==
      String(packages.authority.provenance.sourceAuthorityId) ||
    target.targetDeviceId !== stored.deviceId ||
    target.targetFactorVerificationDigestB64u !== stored.targetFactorVerificationDigestB64u ||
    signerPackage.encryptedTargetClientShare.recipientPublicKeyB64u !==
      target.clientRecipientPublicKeyB64u ||
    sourceScope.wallet_id !== String(stored.walletId) ||
    targetScope.wallet_id !== String(stored.walletId) ||
    !mpcMaterialActivationRefsEqual(
      routerAbMpcMaterialActivationRefFromWire(sourceScope.material_activation),
      source.activation,
    ) ||
    sourceScope.public_identity.client_share_retry_counter !==
      targetScope.public_identity.client_share_retry_counter ||
    sourceScope.public_identity.server_share_retry_counter !==
      targetScope.public_identity.server_share_retry_counter ||
    targetScope.signing_worker.server_id !== target.activation.signingWorker ||
    targetScope.public_identity.derivation_client_share_public_key33_b64u !==
      receipt.binding.targetClientPublicKey33B64u ||
    targetScope.public_identity.server_public_key33_b64u !== receipt.targetRelayerPublicKey33B64u ||
    targetScope.public_identity.threshold_public_key33_b64u !== receipt.thresholdPublicKey33B64u ||
    targetScope.public_identity.ethereum_address20_b64u !==
      receipt.thresholdEthereumAddress20B64u ||
    authorityActivation.signer.walletId !== stored.walletId ||
    authorityActivation.signer.thresholdPublicKey33B64u !== receipt.thresholdPublicKey33B64u ||
    authorityEthereumAddress !== receipt.thresholdEthereumAddress20B64u
  ) {
    return null;
  }
  return {
    walletId: stored.walletId,
    authorityId: stored.authorityId,
    walletAuthMethodId: stored.authMethodId,
    linkSessionId: stored.linkSessionId,
    deviceId: stored.deviceId,
    materialActivation: signerPackage.materialActivation,
    signer: authorityActivation.signer,
    activationReceipt: receipt,
    installedRecordSetDigestB64u: stored.installedRecordSetDigestB64u,
    activatedAtMs: stored.activatedAtMs,
  };
}

function ecdsaAuthorityEvmAddressB64u(value: string): string | null {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) return null;
  const bytes = new Uint8Array(20);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return base64UrlEncode(bytes);
}

function parseStoredInstallationRow(row: Readonly<Record<string, unknown>>): StoredInstallationRow {
  const packages = parseCommittedAuthorityPackagesV1(parseD1JsonColumn(row.packages_json));
  const linkSessionId = requireParsed(
    parseLinkDeviceSessionId(row.link_session_id),
    'link_session_id',
  );
  const authorityId = requireParsed(parseWalletAuthorityId(row.authority_id), 'authority_id');
  const walletId = requireParsed(parseWalletId(row.wallet_id), 'wallet_id');
  const authMethodId = requireParsed(parseWalletAuthMethodId(row.auth_method_id), 'auth_method_id');
  const deviceId = requireParsed(parseDeviceId(row.device_id), 'device_id');
  const packageSetDigestB64u = requireDigest(
    row.package_set_digest_b64u,
    'package_set_digest_b64u',
  );
  const targetFactorVerificationDigestB64u = requireDigest(
    row.target_factor_verification_digest_b64u,
    'target_factor_verification_digest_b64u',
  );
  const targetFactorVerifiedAtMs = requireTime(
    row.target_factor_verified_at_ms,
    'target_factor_verified_at_ms',
  );
  const sourceManifestDigestB64u = requireDigest(
    row.source_manifest_digest_b64u,
    'source_manifest_digest_b64u',
  );
  const deliveryRecipientPublicKey65B64u =
    row.delivery_recipient_public_key_b64u == null
      ? null
      : requireP256PublicKey(
          row.delivery_recipient_public_key_b64u,
          'delivery_recipient_public_key_b64u',
        );
  if (
    packages.authority.authorityId !== authorityId ||
    packages.authority.walletId !== walletId ||
    packages.authMethod.walletAuthMethodId !== authMethodId ||
    packages.packageSetDigestB64u !== packageSetDigestB64u
  ) {
    throw new Error('stored authority installation identity does not match packages');
  }
  const serverReservationIds = parseServerReservationIds(
    parseD1JsonColumn(row.server_reservation_ids_json),
  );
  const installedRecordSetDigestB64u =
    row.installed_record_set_digest_b64u == null
      ? null
      : requireDigest(row.installed_record_set_digest_b64u, 'installed_record_set_digest_b64u');
  const activatedAtMs =
    row.activated_at_ms == null ? null : requireTime(row.activated_at_ms, 'activated_at_ms');
  return {
    linkSessionId,
    authorityId,
    walletId,
    authMethodId,
    deviceId,
    packageSetDigestB64u,
    targetFactorVerificationDigestB64u,
    targetFactorVerifiedAtMs,
    sourceManifestDigestB64u,
    deliveryRecipientPublicKey65B64u,
    packages,
    serverReservationIds,
    installedRecordSetDigestB64u,
    activatedAtMs,
  };
}

function parseStoredCredentialDelivery(
  row: Readonly<Record<string, unknown>>,
): LinkedDeviceWalletSessionCredentialDeliveryV1 {
  const envelope = parseD1JsonColumn(row.sealed_envelope_json);
  return parseLinkedDeviceWalletSessionCredentialDeliveryV1({
    kind: 'linked_device_wallet_session_credential_delivery_v1',
    aad: {
      kind: 'linked_device_wallet_session_credential_delivery_aad_v1',
      namespace: row.namespace,
      orgId: row.org_id,
      projectId: row.project_id,
      envId: row.env_id,
      tenantId: row.tenant_id,
      principalId: row.principal_id,
      linkSessionId: row.link_session_id,
      walletId: row.wallet_id,
      authorityId: row.authority_id,
      walletAuthMethodId: row.wallet_auth_method_id,
      authorizationId: row.authorization_id,
      walletSessionId: row.wallet_session_id,
      quotaId: row.quota_id,
      credentialDigestB64u: row.credential_digest_b64u,
      recipientPublicKey65B64u: row.recipient_public_key_b64u,
      issuedAtMs: row.issued_at_ms,
      expiresAtMs: row.expires_at_ms,
    },
    aadDigestB64u: row.aad_digest_b64u,
    recipientBindingDigestB64u: row.recipient_binding_digest_b64u,
    envelope,
    envelopeDigestB64u: row.sealed_envelope_digest_b64u,
    installationReceiptDigestB64u: row.installation_receipt_digest_b64u,
  });
}

function buildInstallationReceiptFromStoredInstallation(
  stored: StoredInstallationRow,
): LocalAuthorityInstallationReceiptV1 {
  if (stored.installedRecordSetDigestB64u === null || stored.activatedAtMs === null) {
    throw new LinkedDeviceActivationIntegrityErrorV1(
      'active linked-device installation has no activation receipt',
    );
  }
  return {
    kind: 'local_authority_installation_receipt_v1',
    authorityId: stored.authorityId,
    walletId: stored.walletId,
    authMethodId: stored.authMethodId,
    deviceId: stored.deviceId,
    packageSetDigestB64u: stored.packageSetDigestB64u,
    installedActivationRefs: stored.packages.authority.signerActivations,
    installedRecordSetDigestB64u: stored.installedRecordSetDigestB64u,
    targetFactorVerificationDigestB64u: stored.targetFactorVerificationDigestB64u,
    installedAtMs: stored.activatedAtMs,
  };
}

function assertAcknowledgementMatchesCleanupReceipt(
  acknowledgement: LocalAuthorityActivationFinalAckV1,
  cleanupReceipt: LinkedDeviceActivationCleanupReceiptV1,
): void {
  if (
    acknowledgement.linkSessionId !== cleanupReceipt.linkSessionId ||
    acknowledgement.authorityId !== cleanupReceipt.authorityId ||
    acknowledgement.packageSetDigestB64u !== cleanupReceipt.packageSetDigestB64u ||
    acknowledgement.authorizationId !== cleanupReceipt.authorizationId ||
    acknowledgement.walletSessionId !== cleanupReceipt.walletSessionId ||
    acknowledgement.credentialDigestB64u !== cleanupReceipt.credentialDigestB64u ||
    acknowledgement.installationReceiptDigestB64u !==
      cleanupReceipt.installationReceiptDigestB64u ||
    acknowledgement.acknowledgedAtMs !== cleanupReceipt.acknowledgedAtMs
  ) {
    throw new LinkedDeviceActivationIntegrityErrorV1(
      'activation acknowledgement does not match the cleanup receipt',
    );
  }
}

async function assertCleanupReceiptMatchesDeliveryRow(
  cleanupReceipt: LinkedDeviceActivationCleanupReceiptV1,
  row: Readonly<Record<string, unknown>>,
): Promise<void> {
  const devicePublicKeyDigestB64u = await computeLinkedDevicePublicKeyDigestV1(
    cleanupReceipt.devicePublicKeyB64u,
  );
  if (devicePublicKeyDigestB64u !== cleanupReceipt.devicePublicKeyDigestB64u) {
    throw new LinkedDeviceActivationIntegrityErrorV1(
      'activation cleanup receipt device key digest is invalid',
    );
  }
  const identityMatches =
    String(row.link_session_id) === String(cleanupReceipt.linkSessionId) &&
    String(row.wallet_id) === String(cleanupReceipt.walletId) &&
    String(row.authority_id) === String(cleanupReceipt.authorityId) &&
    String(row.wallet_auth_method_id) === String(cleanupReceipt.walletAuthMethodId) &&
    String(row.authorization_id) === String(cleanupReceipt.authorizationId) &&
    String(row.wallet_session_id) === String(cleanupReceipt.walletSessionId) &&
    String(row.credential_digest_b64u) === String(cleanupReceipt.credentialDigestB64u) &&
    String(row.installation_receipt_digest_b64u) ===
      String(cleanupReceipt.installationReceiptDigestB64u) &&
    Number(row.acknowledged_at_ms) === cleanupReceipt.acknowledgedAtMs &&
    String(row.acknowledgement_auth_package_set_digest_b64u) ===
      String(cleanupReceipt.packageSetDigestB64u) &&
    Number(row.acknowledgement_auth_expires_at_ms) === cleanupReceipt.expiresAtMs;
  if (!identityMatches) {
    throw new LinkedDeviceActivationIntegrityErrorV1(
      'activation cleanup receipt does not match the delivery row',
    );
  }
}

function parseAuthorityAllocation(row: Readonly<Record<string, unknown>>): AuthorityAllocation {
  return {
    authorityId: requireParsed(parseWalletAuthorityId(row.authority_id), 'authority_id'),
    walletId: requireParsed(parseWalletId(row.wallet_id), 'wallet_id'),
    enrollmentId: requireText(row.enrollment_id, 'enrollment_id'),
    deviceId: requireParsed(parseDeviceId(row.device_id), 'device_id'),
  };
}

function assertAuthorityAllocationMatches(
  allocation: AuthorityAllocation,
  input: CommitPendingAuthorityInputV1,
  existing: StoredInstallationRow | null,
): void {
  if (
    allocation.walletId !== input.walletId ||
    allocation.enrollmentId !== input.enrollmentId ||
    allocation.deviceId !== input.targetDeviceId ||
    (existing !== null && allocation.authorityId !== existing.authorityId)
  ) {
    throw new Error('wallet authority allocation does not match the link session');
  }
}

async function assertStoredPackageDigest(stored: StoredInstallationRow): Promise<void> {
  if (stored.packages.authority.provenance.kind !== 'device_link') {
    throw new Error('stored authority installation provenance is invalid');
  }
  const expected = await computeCommittedSignerPackageSetDigestB64u({
    authorityId: stored.authorityId,
    walletId: stored.walletId,
    enrollmentId: stored.packages.authority.provenance.enrollmentId,
    linkSessionId: stored.linkSessionId,
    deviceId: stored.deviceId,
    authMethodId: stored.authMethodId,
    permissions: stored.packages.authority.permissions,
    sourceManifestDigestB64u: stored.sourceManifestDigestB64u,
    signerPackages: stored.packages.signerPackages,
    ed25519ExportRootPackageDigestB64u: stored.packages.ed25519ExportRootPackage
      ? await digestJson(stored.packages.ed25519ExportRootPackage)
      : null,
    targetFactorVerificationDigestB64u: stored.targetFactorVerificationDigestB64u,
  });
  if (expected !== stored.packageSetDigestB64u) {
    throw new Error(
      'stored authority installation package digest does not match its canonical contents',
    );
  }
}

function parseServerReservationIds(raw: unknown): Readonly<{
  readonly ed25519?: ServerReservationRecordV1<'ed25519'>;
  readonly ecdsa_secp256k1?: ServerReservationRecordV1<'ecdsa_secp256k1'>;
}> {
  const record = requireRecord(raw, 'server reservation ids');
  requireExactKeys(record, ['ed25519', 'ecdsa_secp256k1'], 'server reservation ids');
  const result: {
    ed25519?: ServerReservationRecordV1<'ed25519'>;
    ecdsa_secp256k1?: ServerReservationRecordV1<'ecdsa_secp256k1'>;
  } = {};
  if (record.ed25519 !== undefined && record.ed25519 !== null) {
    result.ed25519 = parseEd25519ServerReservationRecord(record.ed25519);
  }
  if (record.ecdsa_secp256k1 !== undefined && record.ecdsa_secp256k1 !== null) {
    result.ecdsa_secp256k1 = parseEcdsaServerReservationRecord(record.ecdsa_secp256k1);
  }
  return result;
}

function parseEd25519ServerReservationRecord(raw: unknown): ServerReservationRecordV1<'ed25519'> {
  const record = requireRecord(raw, 'Ed25519 server reservation');
  requireExactKeys(record, ['reservationId', 'preparation'], 'Ed25519 server reservation');
  const preparationRecord = requireRecord(record.preparation, 'Ed25519 reservation preparation');
  requireExactKeys(
    preparationRecord,
    ['kind', 'sourceContribution', 'targetBinding', 'applicationBinding'],
    'Ed25519 reservation preparation',
  );
  if (preparationRecord.kind !== 'ordinary_ed25519_signer_material_reservation_preparation_v1') {
    throw new Error('Ed25519 reservation preparation kind is invalid');
  }
  const sourceContribution = parseLinkedDeviceOrdinaryMaterialSourceContributionV1(
    preparationRecord.sourceContribution,
  );
  if (sourceContribution.keyFamily !== 'ed25519') {
    throw new Error('Ed25519 reservation source contribution family is invalid');
  }
  const targetBinding = parseRouterAbEd25519YaoCeremonyBindingV1(preparationRecord.targetBinding);
  const applicationBinding = parseRouterAbEd25519YaoApplicationBindingFactsV1(
    preparationRecord.applicationBinding,
  );
  if (targetBinding.operation !== 'registration') {
    throw new Error('Ed25519 target binding must use registration');
  }
  return {
    reservationId: requireReservationId(record.reservationId, 'Ed25519 server reservation id'),
    preparation: {
      kind: 'ordinary_ed25519_signer_material_reservation_preparation_v1',
      sourceContribution,
      targetBinding,
      applicationBinding,
    },
  };
}

function parseEcdsaServerReservationRecord(
  raw: unknown,
): ServerReservationRecordV1<'ecdsa_secp256k1'> {
  const record = requireRecord(raw, 'ECDSA server reservation');
  requireExactKeys(record, ['reservationId', 'preparation'], 'ECDSA server reservation');
  const preparationRecord = requireRecord(record.preparation, 'ECDSA reservation preparation');
  requireExactKeys(
    preparationRecord,
    ['kind', 'sourceDerivation', 'sourceContribution'],
    'ECDSA reservation preparation',
  );
  if (preparationRecord.kind !== 'ordinary_ecdsa_signer_material_reservation_preparation_v1') {
    throw new Error('ECDSA reservation preparation kind is invalid');
  }
  return {
    reservationId: requireReservationId(record.reservationId, 'ECDSA server reservation id'),
    preparation: {
      kind: 'ordinary_ecdsa_signer_material_reservation_preparation_v1',
      sourceDerivation: parseLinkedDeviceEcdsaSourceDerivationV1(
        preparationRecord.sourceDerivation,
      ),
      sourceContribution: parseLinkedDeviceEcdsaSourceContributionPackageV1(
        preparationRecord.sourceContribution,
      ),
    },
  };
}

function requireRecord(raw: unknown, label: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error(`${label} is invalid`);
  return raw as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  const expected = new Set(keys);
  if (
    Object.keys(record).length !== keys.length ||
    Object.keys(record).some((key) => !expected.has(key))
  ) {
    throw new Error(`${label} contains unknown or missing fields`);
  }
}

function requireReservationId(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !raw.trim()) throw new Error(`${label} is invalid`);
  return raw;
}

function requireText(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !raw.trim()) throw new Error(`${label} is invalid`);
  return raw;
}

function assertRetryInput(
  stored: StoredInstallationRow,
  input: VerifiedLinkInputV1,
  expectedAuthorityId: WalletAuthorityId,
): void {
  if (
    stored.authorityId !== expectedAuthorityId ||
    stored.walletId !== input.walletId ||
    stored.linkSessionId !== input.linkSessionId ||
    stored.deviceId !== input.targetDeviceId ||
    stored.targetFactorVerificationDigestB64u !== input.targetFactor.verificationDigestB64u ||
    stored.authMethodId !== input.targetFactor.authMethod.walletAuthMethodId
  ) {
    throw new Error('pending authority retry does not match the committed link input');
  }
}

function assertReceiptMatchesInstallation(
  receipt: LocalAuthorityInstallationReceiptV1,
  stored: StoredInstallationRow,
  nowMs: number,
): void {
  if (
    receipt.walletId !== stored.walletId ||
    receipt.authMethodId !== stored.authMethodId ||
    receipt.deviceId !== stored.deviceId ||
    receipt.packageSetDigestB64u !== stored.packageSetDigestB64u ||
    receipt.targetFactorVerificationDigestB64u !== stored.targetFactorVerificationDigestB64u
  ) {
    throw new Error(
      'local authority installation receipt identity does not match committed packages',
    );
  }
  if (
    !sameActivationSet(receipt.installedActivationRefs, stored.packages.authority.signerActivations)
  )
    throw new Error(
      'local authority installation activation refs do not match committed authority',
    );
  if (
    !Number.isSafeInteger(receipt.installedAtMs) ||
    receipt.installedAtMs < stored.targetFactorVerifiedAtMs ||
    receipt.installedAtMs < stored.packages.authority.createdAtMs ||
    receipt.installedAtMs > nowMs
  )
    throw new Error('local authority installation receipt time is invalid');
  if (
    stored.installedRecordSetDigestB64u &&
    stored.installedRecordSetDigestB64u !== receipt.installedRecordSetDigestB64u
  )
    throw new Error(
      'local authority installation receipt record digest conflicts with prior receipt',
    );
  if (stored.activatedAtMs !== null && stored.activatedAtMs !== receipt.installedAtMs)
    throw new Error('local authority installation time conflicts with prior receipt');
}

function sameActivationSet(
  left: WalletSignerActivationSetV1,
  right: WalletSignerActivationSetV1,
): boolean {
  if (left.keyFamilies.length !== right.keyFamilies.length) return false;
  if (left.keyFamilies[0] !== right.keyFamilies[0]) return false;
  const leftEd25519 = left.ed25519;
  const rightEd25519 = right.ed25519;
  if (leftEd25519) {
    if (!rightEd25519) return false;
    if (!sameEd25519Signer(leftEd25519.signer, rightEd25519.signer)) return false;
    if (
      !mpcMaterialActivationRefsEqual(
        leftEd25519.materialActivation,
        rightEd25519.materialActivation,
      )
    )
      return false;
  }
  const leftEcdsa = left.ecdsa;
  const rightEcdsa = right.ecdsa;
  if (leftEcdsa) {
    if (!rightEcdsa) return false;
    if (!sameEcdsaSigner(leftEcdsa.signer, rightEcdsa.signer)) return false;
    if (
      !mpcMaterialActivationRefsEqual(leftEcdsa.materialActivation, rightEcdsa.materialActivation)
    )
      return false;
  }
  return true;
}

function sameEd25519Signer(
  left: ExactAdministeredSignerV1,
  right: ExactAdministeredSignerV1,
): boolean {
  return (
    left.keyFamily === 'ed25519' &&
    right.keyFamily === 'ed25519' &&
    left.walletId === right.walletId &&
    left.walletKeyId === right.walletKeyId &&
    left.registeredPublicKeyB64u === right.registeredPublicKeyB64u
  );
}

function sameEcdsaSigner(
  left: ExactAdministeredSignerV1,
  right: ExactAdministeredSignerV1,
): boolean {
  return (
    left.keyFamily === 'ecdsa_secp256k1' &&
    right.keyFamily === 'ecdsa_secp256k1' &&
    left.walletId === right.walletId &&
    left.walletKeyId === right.walletKeyId &&
    left.thresholdPublicKey33B64u === right.thresholdPublicKey33B64u &&
    left.evmAddress === right.evmAddress
  );
}

function sameAuthority(left: WalletAuthorityV1, right: PendingWalletAuthorityV1): boolean {
  if (left.state === 'revoked') return false;
  if (left.state === 'pending_local_install')
    return alphabetizeStringify(left) === alphabetizeStringify(right);
  return (
    left.authorityId === right.authorityId &&
    left.walletId === right.walletId &&
    left.principal.deviceId === right.principal.deviceId &&
    left.provenance.kind === 'device_link' &&
    right.provenance.kind === 'device_link' &&
    left.provenance.enrollmentId === right.provenance.enrollmentId &&
    left.provenance.sourceAuthorityId === right.provenance.sourceAuthorityId &&
    left.provenance.linkSessionId === right.provenance.linkSessionId &&
    alphabetizeStringify(left.permissions) === alphabetizeStringify(right.permissions) &&
    sameActivationSet(left.signerActivations, right.signerActivations) &&
    left.signerActivationSetDigestB64u === right.signerActivationSetDigestB64u
  );
}

function sameAuthMethod(
  left: WalletAuthMethodRecordV2,
  right: CommittedAuthorityPackagesV1['authMethod'],
): boolean {
  if (
    left.walletAuthMethodId !== right.walletAuthMethodId ||
    left.walletAuthorityId !== right.walletAuthorityId ||
    left.walletId !== right.walletId
  )
    return false;
  if (
    !('kind' in left) ||
    !('kind' in right) ||
    left.kind !== right.kind ||
    left.kind === undefined
  )
    return false;
  if (left.kind === 'passkey') {
    return (
      right.kind === 'passkey' &&
      left.rpId === right.rpId &&
      left.credentialIdB64u === right.credentialIdB64u &&
      left.credentialPublicKeyB64u === right.credentialPublicKeyB64u &&
      left.counter === right.counter
    );
  }
  return (
    right.kind === 'email_otp' &&
    left.emailHashHex === right.emailHashHex &&
    left.registrationAuthorityId === right.registrationAuthorityId
  );
}

async function digestJson(value: unknown): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

async function sealLinkedDeviceWalletSessionCredentialV1(input: {
  readonly scope: D1WalletAuthorityStoreScope;
  readonly tenantId: LinkedDeviceWalletSessionCredentialDeliveryAadV1['tenantId'];
  readonly principalId: LinkedDeviceWalletSessionCredentialDeliveryAadV1['principalId'];
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorizationId: LinkedDeviceWalletSessionCredentialDeliveryAadV1['authorizationId'];
  readonly walletSessionId: LinkedDeviceWalletSessionCredentialDeliveryAadV1['walletSessionId'];
  readonly quotaId: LinkedDeviceWalletSessionCredentialDeliveryAadV1['quotaId'];
  readonly credentialDigestB64u: DigestB64u;
  readonly recipientPublicKey65B64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly installationReceiptDigestB64u: DigestB64u;
  readonly operationCredential: {
    readonly kind: 'opaque_wallet_session_operation_credential_v1';
    readonly token: string;
    readonly walletSessionId: LinkedDeviceWalletSessionCredentialDeliveryAadV1['walletSessionId'];
  };
}): Promise<LinkedDeviceWalletSessionCredentialDeliveryV1> {
  const recipientPublicKey = requireP256PublicKey(
    input.recipientPublicKey65B64u,
    'recipientPublicKey65B64u',
  );
  const aad: LinkedDeviceWalletSessionCredentialDeliveryAadV1 = {
    kind: 'linked_device_wallet_session_credential_delivery_aad_v1',
    namespace: input.scope.namespace,
    orgId: input.scope.orgId,
    projectId: input.scope.projectId,
    envId: input.scope.envId,
    tenantId: input.tenantId,
    principalId: input.principalId,
    linkSessionId: input.linkSessionId,
    walletId: input.walletId,
    authorityId: input.authorityId,
    walletAuthMethodId: input.walletAuthMethodId,
    authorizationId: input.authorizationId,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    credentialDigestB64u: input.credentialDigestB64u,
    recipientPublicKey65B64u: recipientPublicKey,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  };
  const aadBytes = new TextEncoder().encode(
    encodeLinkedDeviceWalletSessionCredentialDeliveryAadV1(aad),
  );
  const plaintext = new TextEncoder().encode(alphabetizeStringify(input.operationCredential));
  let recipientBytes: Uint8Array | null = null;
  let nonce: Uint8Array | null = null;
  try {
    recipientBytes = base64UrlDecode(recipientPublicKey);
    const importedRecipient = await crypto.subtle.importKey(
      'raw',
      recipientBytes,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    const serverKeyPair = (await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveKey'],
    )) as CryptoKeyPair;
    const encryptionKey = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: importedRecipient },
      serverKeyPair.privateKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
    nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce, additionalData: aadBytes, tagLength: 128 },
        encryptionKey,
        plaintext,
      ),
    );
    const serverPublicKey = new Uint8Array(
      await crypto.subtle.exportKey('raw', serverKeyPair.publicKey),
    );
    try {
      const envelope = {
        kind: 'linked_device_wallet_session_credential_envelope_v1' as const,
        algorithm: 'p256-ecdh-aes256gcm-v1' as const,
        serverEphemeralPublicKey65B64u: base64UrlEncode(serverPublicKey),
        nonce12B64u: base64UrlEncode(nonce),
        ciphertextB64u: base64UrlEncode(ciphertext),
      };
      return {
        kind: 'linked_device_wallet_session_credential_delivery_v1',
        aad,
        aadDigestB64u:
          await computeLinkedDeviceWalletSessionCredentialDeliveryAadDigestB64u(aad),
        recipientBindingDigestB64u: await digestJson({
          domain: 'seams/linked-device/delivery-recipient/v1',
          recipientPublicKey65B64u: recipientPublicKey,
        }),
        envelope,
        envelopeDigestB64u:
          await computeLinkedDeviceWalletSessionCredentialEnvelopeDigestB64u(envelope),
        installationReceiptDigestB64u: input.installationReceiptDigestB64u,
      };
    } finally {
      serverPublicKey.fill(0);
      ciphertext.fill(0);
    }
  } finally {
    recipientBytes?.fill(0);
    nonce?.fill(0);
    aadBytes.fill(0);
    plaintext.fill(0);
  }
}

function requireP256PublicKey(raw: unknown, label: string): string {
  const encoded = requireText(raw, label);
  const bytes = base64UrlDecode(encoded);
  try {
    if (bytes.length !== 65 || bytes[0] !== 4 || base64UrlEncode(bytes) !== encoded) {
      throw new Error(`${label} must be a canonical uncompressed P-256 point`);
    }
    return encoded;
  } finally {
    bytes.fill(0);
  }
}

function requireParsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label} ${result.error.message}`);
  return result.value;
}

function requireDigest(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error: unknown) {
    throw new Error(`${label} ${errorMessage(error)}`);
  }
}

function requireTime(raw: unknown, label: string): number {
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error(`${label} must be a non-negative safe integer`);
  return value;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
