import { expect, test } from '@playwright/test';
import type { ClientUserData } from '../../packages/sdk-web/src/core/accountData/near/nearAccountData.types';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import type { NearEd25519YaoOperationMaterial } from '../../packages/sdk-web/src/core/signingEngine/interfaces/near';
import {
  activateColdEmailOtpEd25519YaoUnlockedRecoveryV1,
  prepareColdEmailOtpEd25519YaoRecoveryV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoCapabilityRecovery';
import { resolveEmailOtpEd25519YaoColdRecoveryV1 } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoLogin';
import { recoverEmailOtpEd25519YaoWorkerClientV1 } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoWorkerClient';
import type { EmailOtpEd25519YaoPublicationInput } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoPublication';
import type { EmailOtpEd25519YaoPendingFactorHandle } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoRootVault';
import type { WorkerOperationContext } from '../../packages/sdk-web/src/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpEd25519YaoRecoveryBootstrapV1 } from '../../packages/sdk-web/src/core/signingEngine/workerManager/workerTypes';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';
import type {
  Ed25519YaoActiveClientIdentityV1,
  Ed25519YaoActiveClientLookupScopeV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../packages/sdk-web/src/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';
import type { CurrentEd25519SealedSessionRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  recoverEmailOtpEd25519YaoFromSealedSessionV1,
  resolveEmailOtpEd25519YaoExportContextV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoSealedRecovery';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parseThresholdEd25519SessionId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildActiveWalletSessionAuthorizationProjection } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { resolveThresholdEd25519CommitQueueKey } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/commitQueue';
import { exactEd25519SigningLaneIdentity } from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildNamedNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
} from '../../packages/shared-ts/src/utils/walletCapabilityBindings';
import { parseNamedNearAccountId } from '../../packages/shared-ts/src/utils/near';
import {
  parseRouterAbMpcMaterialActivationRef,
  routerAbMpcMaterialActivationRefToWire,
} from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildEmailOtpEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';

const WALLET_ID = walletIdFromString('email-otp-ed25519-sealed-runtime-wallet');
const NEAR_ACCOUNT_ID = toAccountId('email-otp-ed25519-runtime.testnet');
const NEAR_ED25519_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString(
  'email-otp-ed25519-runtime-key',
);
const THRESHOLD_SESSION_ID = 'email-otp-ed25519-sealed-runtime-session';
const WALLET_SESSION_ID = unwrapDomainId(parseWalletSessionId('email-otp-ed25519-wallet-session'));
const WALLET_SESSION_QUOTA_ID = unwrapDomainId(
  parseMpcWalletSigningQuotaId('email-otp-ed25519-wallet-session-quota'),
);
const PROVIDER_SUBJECT = 'google:email-otp-ed25519-runtime';
const EMAIL_HASH_HEX = 'email-otp-ed25519-runtime-hash';
const RP_ID = 'wallet.example.test';
const RELAYER_URL = 'https://relay.example.test';
const SIGNING_WORKER_ID = 'email-otp-ed25519-runtime-worker';
const SIGNING_ROOT_ID = 'email-otp-ed25519-sealed-runtime-project:test';
const PARTICIPANT_IDS = [1, 2] as const;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'email-otp-ed25519-runtime-org',
  projectId: 'email-otp-ed25519-sealed-runtime-project',
  envId: 'test',
  signingRootVersion: 'v1',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: SIGNING_WORKER_ID,
} as const;
const REGISTERED_PUBLIC_KEY = new Uint8Array(32).fill(7);
const PRIOR_CAPABILITY_BINDING = new Array<number>(32).fill(1);
const MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'email-otp-ed25519-runtime-material',
  String(WALLET_ID),
  SIGNING_WORKER_ID,
);
const RECOVERY_MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'email-otp-ed25519-recovery',
  String(WALLET_ID),
  SIGNING_WORKER_ID,
  String(MATERIAL_ACTIVATION.keyBinding),
);

function materialActivationFromWire(value: unknown) {
  const wire = parseRouterAbMpcMaterialActivationRef(value);
  const parsed = parseMpcMaterialActivationRef({
    kind: wire.kind,
    activationId: wire.activation_id,
    capability: wire.capability,
    materialOwner: wire.material_owner,
    keyBinding: wire.key_binding,
    lifecycleBinding: wire.lifecycle_binding,
    signingWorker: wire.signing_worker,
  });
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function exportLaneIdentity() {
  const account = parseNamedNearAccountId(NEAR_ACCOUNT_ID);
  if (!account.ok) throw new Error(account.message);
  return exactEd25519SigningLaneIdentity({
    signer: buildNearEd25519SignerBinding({
      account: buildNamedNearAccountBinding({
        wallet: buildWalletIdentity({ walletId: WALLET_ID }),
        nearAccountId: account.value,
      }),
      nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
      signerSlot: 1,
    }),
    auth: { kind: 'email_otp', providerSubjectId: PROVIDER_SUBJECT },
    walletSessionId: WALLET_SESSION_ID,
    quotaId: WALLET_SESSION_QUOTA_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
}

function unwrapDomainId<T>(
  result: { ok: true; value: T } | { ok: false; error: { message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function walletSessionJwt(version: string, quotaId = WALLET_SESSION_QUOTA_ID): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'router_ab_ed25519_wallet_session_v1',
    sub: String(WALLET_ID),
    walletId: String(WALLET_ID),
    nearAccountId: String(NEAR_ACCOUNT_ID),
    nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
    walletSessionId: WALLET_SESSION_ID,
    quotaId,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    relayerKeyId: SIGNING_WORKER_ID,
    rpId: RP_ID,
    participantIds: [...PARTICIPANT_IDS],
    version,
  })}.fixture`;
}

async function readActiveEmailOtpWalletSessionAuthorization() {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: PROVIDER_SUBJECT,
    emailHashHex: EMAIL_HASH_HEX,
  });
  const authorizationSessionId = unwrapDomainId(
    parseSeamsSessionId('email-otp-ed25519-app-session'),
  );
  return {
    kind: 'found' as const,
    projection: buildActiveWalletSessionAuthorizationProjection({
      walletId: WALLET_ID,
      authorizationSessionId,
      walletSessionId: WALLET_SESSION_ID,
      quotaId: WALLET_SESSION_QUOTA_ID,
      walletSessionJwt: walletSessionJwt('sealed-refresh'),
      authMethod: 'email_otp',
      authority: await walletAuthAuthorityRef({ authority }),
      expiresAtMs: Date.now() + 60_000,
    }),
  };
}

function activeMetadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
  return {
    kind: 'router_ab_ed25519_yao_active_client_v1',
    scope: {
      lifecycle_id: 'email-otp-ed25519-registration-lifecycle',
      root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
      account_id: String(WALLET_ID),
      threshold_session_id: THRESHOLD_SESSION_ID,
      signer_set_id: 'near_ed25519:slot:1',
      signing_worker_id: SIGNING_WORKER_ID,
      material_activation: routerAbMpcMaterialActivationRefToWire(MATERIAL_ACTIVATION),
    },
    applicationBinding: {
      wallet_id: String(WALLET_ID),
      near_ed25519_signing_key_id: String(NEAR_ED25519_SIGNING_KEY_ID),
      signing_root_id: SIGNING_ROOT_ID,
      key_creation_signer_slot: 1,
    },
    participantIds: PARTICIPANT_IDS,
    registeredPublicKey: REGISTERED_PUBLIC_KEY.slice(),
    signingWorkerVerifyingShare: new Uint8Array(32),
    stateEpoch: 1n,
    transcript: new Uint8Array(32),
    activeCapabilityBinding: [...PRIOR_CAPABILITY_BINDING],
    materialActivation: MATERIAL_ACTIVATION,
  };
}

function recoveryBootstrap(args: {
  remainingUses: number;
  prior: RouterAbEd25519YaoActiveClientMetadataV1;
  substitutePublicKey: boolean;
  substituteParticipantIds: boolean;
  substituteSignerSetId: boolean;
  walletSessionJwt?: string;
  materialActivation?: typeof RECOVERY_MATERIAL_ACTIVATION;
}): EmailOtpEd25519YaoRecoveryBootstrapV1 {
  const registeredPublicKey = args.substitutePublicKey
    ? new Array<number>(32).fill(9)
    : [...args.prior.registeredPublicKey];
  const participantIds = args.substituteParticipantIds ? ([1, 3] as const) : PARTICIPANT_IDS;
  return {
    kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
    session: {
      sessionKind: 'jwt',
      walletSessionJwt:
        args.walletSessionJwt ?? walletSessionJwt('recovered'),
      walletId: WALLET_ID,
      nearAccountId: String(NEAR_ACCOUNT_ID),
      nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
      authorityScope: {
        kind: 'email_otp',
        provider: 'google',
        providerUserId: PROVIDER_SUBJECT,
      },
      thresholdSessionId: THRESHOLD_SESSION_ID,
      walletSessionId: WALLET_SESSION_ID,
      quotaId: WALLET_SESSION_QUOTA_ID,
      expiresAtMs: Date.now() + 60_000,
      participantIds,
      remainingUses: args.remainingUses,
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    },
    capability: {
      kind: 'router_ab_ed25519_yao_active_capability_v1',
      materialActivation: args.materialActivation ?? MATERIAL_ACTIVATION,
      activeCapabilityBinding: [...PRIOR_CAPABILITY_BINDING],
      registeredPublicKey,
      nearAccountId: String(NEAR_ACCOUNT_ID),
      applicationBinding: args.prior.applicationBinding,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      participantIds,
      lifecycle: {
        lifecycleId: args.prior.scope.lifecycle_id,
        rootShareEpoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
        accountId: String(WALLET_ID),
        thresholdSessionId: THRESHOLD_SESSION_ID,
        signerSetId: args.substituteSignerSetId
          ? 'near_ed25519:slot:2'
          : args.prior.scope.signer_set_id,
        signingWorkerId: SIGNING_WORKER_ID,
      },
      stateEpoch: Number(args.prior.stateEpoch),
    },
  };
}

class RecoveryWorkerFixture {
  readonly operations: string[] = [];
  loginPayload: Record<string, unknown> | null = null;
  disposedPendingFactor: unknown = null;
  private readonly prior: RouterAbEd25519YaoActiveClientMetadataV1;
  private readonly substitutePublicKey: boolean;
  private readonly substituteParticipantIds: boolean;
  private readonly substituteSignerSetId: boolean;
  private readonly failRecoveryDispatch: boolean;
  private readonly disposeBoundRootResult: boolean;
  private readonly requireFreshMaterialActivation: boolean;

  constructor(args: {
    prior: RouterAbEd25519YaoActiveClientMetadataV1;
    substitutePublicKey: boolean;
    substituteParticipantIds?: boolean;
    substituteSignerSetId?: boolean;
    failRecoveryDispatch?: boolean;
    disposeBoundRootResult?: boolean;
    requireFreshMaterialActivation?: boolean;
  }) {
    this.prior = args.prior;
    this.substitutePublicKey = args.substitutePublicKey;
    this.substituteParticipantIds = args.substituteParticipantIds === true;
    this.substituteSignerSetId = args.substituteSignerSetId === true;
    this.failRecoveryDispatch = args.failRecoveryDispatch === true;
    this.disposeBoundRootResult = args.disposeBoundRootResult !== false;
    this.requireFreshMaterialActivation = args.requireFreshMaterialActivation === true;
  }

  async requestWorkerOperation(args: any): Promise<any> {
    const request = args.request as { type: string; payload: Record<string, any> };
    this.operations.push(request.type);
    switch (request.type) {
      case 'rehydrateEmailOtpEd25519YaoLocalMaterial': {
        const exactCapability = recoveryBootstrap({
          remainingUses: request.payload.remainingUses,
          prior: this.prior,
          substitutePublicKey: this.substitutePublicKey,
          substituteParticipantIds: this.substituteParticipantIds,
          substituteSignerSetId: this.substituteSignerSetId,
        }).capability;
        return {
          ok: true,
          activeClientHandle: 'rehydrated-active-client-1',
          metadata: this.prior,
          ed25519YaoCapability: {
            kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
            session: request.payload.restore.session,
            capability: exactCapability,
          },
        };
      }
      case 'rehydrateEmailOtpEd25519YaoFactor':
        return {
          ok: true,
          pendingFactorHandle: pendingFactorHandle(),
          remainingUses: request.payload.remainingUses,
          expiresAtMs: request.payload.expiresAtMs,
        };
      case 'loginWithEmailOtpWallet': {
        this.loginPayload = request.payload;
        const remainingUses = Number(request.payload.material.ed25519YaoRecovery.remainingUses);
        return {
          kind: 'ed25519_yao_recovery',
          recovery: {
            challengeId: 'challenge-1',
            enrollmentSealKeyVersion: 'email-otp-v1',
            unlockChallengeId: 'unlock-challenge-1',
            unlockChallengeB64u: 'unlock-challenge-b64u',
            clientUnlockPublicKeyB64u: 'client-unlock-public-key',
            unlockSignatureB64u: 'unlock-signature',
          },
          pendingFactorHandle: {
            kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
            handleId: 'pending-factor-1',
            purpose: 'recovery',
            expiresAtMs: Date.now() + 60_000,
          },
          ed25519YaoRecovery: recoveryBootstrap({
            remainingUses,
            prior: this.prior,
            substitutePublicKey: this.substitutePublicKey,
            substituteParticipantIds: this.substituteParticipantIds,
            substituteSignerSetId: this.substituteSignerSetId,
          }),
        };
      }
      case 'bindEmailOtpEd25519YaoRoot':
        return {
          rootHandle: {
            kind: 'email_otp_ed25519_yao_root_handle_v1',
            handleId: 'recovery-root-1',
            purpose: 'recovery',
            expiresAtMs: Date.now() + 60_000,
          },
        };
      case 'recoverEmailOtpEd25519Yao': {
        if (this.failRecoveryDispatch) {
          throw new Error('injected recovery dispatch failure');
        }
        const admission = request.payload.admissionRequest;
        const recoveredMaterialActivation = materialActivationFromWire(
          admission.scope.material_activation,
        );
        if (
          this.requireFreshMaterialActivation &&
          mpcMaterialActivationRefsEqual(recoveredMaterialActivation, this.prior.materialActivation)
        ) {
          throw new Error('fixture recovery material activation did not advance');
        }
        const recoveredMetadata: RouterAbEd25519YaoActiveClientMetadataV1 = {
          kind: 'router_ab_ed25519_yao_active_client_v1',
          scope: admission.scope,
          applicationBinding: this.prior.applicationBinding,
          participantIds: PARTICIPANT_IDS,
          registeredPublicKey: this.prior.registeredPublicKey.slice(),
          signingWorkerVerifyingShare: new Uint8Array(32),
          stateEpoch: this.prior.stateEpoch + 1n,
          transcript: new Uint8Array(32),
          activeCapabilityBinding: [...admission.replacement_capability_binding],
          materialActivation: recoveredMaterialActivation,
        };
        return {
          activeClientHandle: 'recovered-active-client-1',
          metadata: recoveredMetadata,
          activation: {
            binding: {},
            public_receipt: {
              transcript: new Array<number>(32).fill(0),
              registered_public_key: [...this.prior.registeredPublicKey],
              joined_client_commitment: new Array<number>(32).fill(0),
              joined_signing_worker_commitment: new Array<number>(32).fill(0),
              signing_worker_verifying_share: new Array<number>(32).fill(0),
              state_epoch: Number(this.prior.stateEpoch + 1n),
              material_activation: admission.scope.material_activation,
            },
            active_capability_binding: [...admission.replacement_capability_binding],
            retired_capability_binding: [...admission.active_capability_binding],
          },
        };
      }
      case 'disposeEmailOtpEd25519YaoPendingFactor':
        this.disposedPendingFactor = request.payload.pendingFactorHandle;
        return { removed: true };
      case 'disposeEmailOtpEd25519YaoRoot':
        return { removed: this.disposeBoundRootResult };
      case 'disposeEmailOtpEd25519YaoActiveClient':
        return { removed: true };
      default:
        throw new Error(`unexpected worker operation ${request.type}`);
    }
  }

  context(): WorkerOperationContext {
    return this;
  }
}

class RecoveryActivationHarness {
  private readonly previous: NearEd25519YaoOperationMaterial | null;
  activated: NearEd25519YaoOperationMaterial | null = null;
  activateCalls = 0;

  constructor(previous: NearEd25519YaoOperationMaterial | null) {
    this.previous = previous;
  }

  resolve(scope: Ed25519YaoActiveClientLookupScopeV1): NearEd25519YaoOperationMaterial | null {
    return this.previous && scope.walletId === WALLET_ID && scope.nearAccountId === NEAR_ACCOUNT_ID
      ? this.previous
      : null;
  }

  async activate(
    material: NearEd25519YaoOperationMaterial,
  ): Promise<Ed25519YaoActiveClientIdentityV1> {
    this.activateCalls += 1;
    this.activated = material;
    return {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
        material.activeClient.metadata(),
      ),
    };
  }
}

class ColdRecoveryResolutionFixture {
  private readonly users: readonly ClientUserData[];
  private readonly references: readonly Ed25519YaoActiveClientIdentityV1[];

  constructor(args: {
    users: readonly ClientUserData[];
    references: readonly Ed25519YaoActiveClientIdentityV1[];
  }) {
    this.users = args.users;
    this.references = args.references;
  }

  async listUsers(): Promise<readonly ClientUserData[]> {
    return this.users;
  }

  async listPublicCapabilityReferences(): Promise<readonly Ed25519YaoActiveClientIdentityV1[]> {
    return this.references;
  }
}

function resolveNoActiveCapability(): NearEd25519YaoOperationMaterial | null {
  return null;
}

function emailOtpUser(): ClientUserData {
  return {
    walletId: String(WALLET_ID),
    nearAccountId: NEAR_ACCOUNT_ID,
    loginDisplayName: 'email-otp@example.test',
    signerSlot: 1,
    operationalPublicKey: `ed25519:${base58Encode(REGISTERED_PUBLIC_KEY)}`,
    passkeyCredential: {
      id: 'email-otp-public-projection',
      rawId: 'email-otp-public-projection',
    },
    authMethod: 'email_otp',
  };
}

function publicCapabilityReference(): Ed25519YaoActiveClientIdentityV1 {
  return {
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    materialActivation: nearEd25519YaoMaterialActivationFromMetadata(activeMetadata()),
  };
}

function pendingFactorHandle(): EmailOtpEd25519YaoPendingFactorHandle {
  return {
    kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
    handleId: 'pending-factor-1',
    purpose: 'recovery',
    expiresAtMs: Date.now() + 60_000,
  };
}

function buildEmailOtpSealedRecord(args: {
  expiresAtMs: number;
  remainingUses: number;
  materialActivation?: ReturnType<typeof nearEd25519YaoMaterialActivationFromMetadata>;
}): CurrentEd25519SealedSessionRecord {
  return buildEmailOtpEd25519SealedSessionRecordFixture({
    walletId: String(WALLET_ID),
    nearAccountId: String(NEAR_ACCOUNT_ID),
    nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
    thresholdSessionId: THRESHOLD_SESSION_ID,
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses,
    materialActivation: args.materialActivation ?? publicCapabilityReference().materialActivation,
  });
}

async function runEd25519CommitQueueTask<T>(args: {
  task: () => Promise<T>;
}): Promise<T> {
  return await args.task();
}

async function persistRecoveredSessionForTest(): Promise<void> {}

async function unexpectedWarmBootstrapFetch(): Promise<Response> {
  throw new Error('warm bootstrap must not run for unavailable sealed material');
}

async function warmRecoveryBootstrapResponse(args: {
  expiresAtMs: number;
  thresholdExpiresAtMs: number;
  prior: RouterAbEd25519YaoActiveClientMetadataV1;
}): Promise<Record<string, unknown>> {
  const bootstrap = recoveryBootstrap({
    remainingUses: 3,
    prior: args.prior,
    substitutePublicKey: false,
    substituteParticipantIds: false,
    substituteSignerSetId: false,
  });
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: PROVIDER_SUBJECT,
    emailHashHex: EMAIL_HASH_HEX,
  });
  return {
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
    walletId: String(WALLET_ID),
    nearAccountId: String(NEAR_ACCOUNT_ID),
    nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
    signerSlot: 1,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    walletSessionId: WALLET_SESSION_ID,
    quotaId: WALLET_SESSION_QUOTA_ID,
    signingWorkerId: SIGNING_WORKER_ID,
    thresholdExpiresAtMs: args.thresholdExpiresAtMs,
    participantIds: [...PARTICIPANT_IDS],
    authority,
    authorityRef: await walletAuthAuthorityRef({ authority }),
    authorityScope: {
      kind: 'email_otp',
      provider: 'google',
      providerUserId: PROVIDER_SUBJECT,
    },
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    capability: bootstrap.capability,
  };
}

test.describe('Email OTP Ed25519 Yao capability recovery', () => {
  test('silently recovers valid sealed Email OTP material after page refresh', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEmailOtpSealedRecord({ expiresAtMs, remainingUses: 3 });
    const prior = activeMetadata();
    const worker = new RecoveryWorkerFixture({ prior, substitutePublicKey: false });
    const activation = new RecoveryActivationHarness(null);
    let publicationInput: EmailOtpEd25519YaoPublicationInput | null = null;

    const result = await recoverEmailOtpEd25519YaoFromSealedSessionV1({
      subject: {
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        signerSlot: 1,
        thresholdSessionId: THRESHOLD_SESSION_ID,
      },
      expectedMaterialActivation: publicCapabilityReference().materialActivation,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      ports: {
        readExactEd25519SealedSession: async () => sealedRecord,
        readActiveWalletSessionAuthorization: readActiveEmailOtpWalletSessionAuthorization,
        workerContext: worker.context(),
        resolveActiveCapability: activation.resolve.bind(activation),
        activateCapability: activation.activate.bind(activation),
        withThresholdEd25519CommitQueue: runEd25519CommitQueueTask,
        persistRecoveredSession: async (input) => {
          publicationInput = input;
        },
        fetch: async () =>
          new Response(
            JSON.stringify(
              await warmRecoveryBootstrapResponse({
                expiresAtMs,
                thresholdExpiresAtMs: expiresAtMs,
                prior,
              }),
            ),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        nowMs: Date.now,
      },
    });

    expect(result.kind).toBe('recovered');
    expect(worker.operations).toEqual(['rehydrateEmailOtpEd25519YaoLocalMaterial']);
    expect(worker.operations).not.toContain('loginWithEmailOtpWallet');
    expect(activation.activateCalls).toBe(1);
    expect(publicationInput).not.toBeNull();
    expect(publicationInput).not.toHaveProperty('record');
    expect(publicationInput?.publicationContext).toMatchObject({
      rpId: RP_ID,
      provider: 'google',
      providerSubjectId: PROVIDER_SUBJECT,
      emailHashHex: EMAIL_HASH_HEX,
    });
    expect(publicationInput?.walletSessionState.thresholdSessionId).toBe(
      THRESHOLD_SESSION_ID,
    );
    if (result.kind === 'recovered') {
      expect(result.recovery.walletSessionState.remainingUses).toBe(3);
      expect(result.recovery.walletSessionState.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
    }
  });

  test('rejects a superseded activation inside the material-owner queue before recovery', async () => {
    const expectedActivation = publicCapabilityReference().materialActivation;
    const replacementMetadata = activeMetadata();
    replacementMetadata.scope.lifecycle_id = 'email-otp-ed25519-replacement-lifecycle';
    replacementMetadata.materialActivation = buildMpcMaterialActivationRefFixture(
      'email-otp-ed25519-replacement-lifecycle',
      String(WALLET_ID),
      SIGNING_WORKER_ID,
    );
    replacementMetadata.scope.material_activation = routerAbMpcMaterialActivationRefToWire(
      replacementMetadata.materialActivation,
    );
    const replacementActivation =
      nearEd25519YaoMaterialActivationFromMetadata(replacementMetadata);
    const initialRecord = buildEmailOtpSealedRecord({
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 3,
      materialActivation: expectedActivation,
    });
    const replacementRecord = buildEmailOtpSealedRecord({
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 3,
      materialActivation: replacementActivation,
    });
    const worker = new RecoveryWorkerFixture({
      prior: activeMetadata(),
      substitutePublicKey: false,
    });
    const activation = new RecoveryActivationHarness(null);
    let recordReads = 0;
    let queueCalls = 0;
    let persistCalls = 0;

    await expect(
      recoverEmailOtpEd25519YaoFromSealedSessionV1({
        subject: {
          walletId: WALLET_ID,
          nearAccountId: NEAR_ACCOUNT_ID,
          signerSlot: 1,
          thresholdSessionId: THRESHOLD_SESSION_ID,
        },
        expectedMaterialActivation: expectedActivation,
        expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
        rpId: RP_ID,
        relayerUrl: RELAYER_URL,
        authPolicy: 'session',
        ports: {
          readExactEd25519SealedSession: async () => {
            recordReads += 1;
            return recordReads === 1 ? initialRecord : replacementRecord;
          },
          readActiveWalletSessionAuthorization: readActiveEmailOtpWalletSessionAuthorization,
          workerContext: worker.context(),
          resolveActiveCapability: activation.resolve.bind(activation),
          activateCapability: activation.activate.bind(activation),
          withThresholdEd25519CommitQueue: async (queueArgs) => {
            queueCalls += 1;
            expect(queueArgs.queueKey).toBe(
              resolveThresholdEd25519CommitQueueKey({
                materialActivation: expectedActivation,
              }),
            );
            return await queueArgs.task();
          },
          fetch: unexpectedWarmBootstrapFetch,
          persistRecoveredSession: async () => {
            persistCalls += 1;
          },
          nowMs: Date.now,
        },
      }),
    ).rejects.toThrow('superseded before use');
    expect(recordReads).toBe(2);
    expect(queueCalls).toBe(1);
    expect(worker.operations).toEqual([]);
    expect(activation.activateCalls).toBe(0);
    expect(persistCalls).toBe(0);
  });

  test('routes exhausted Email OTP authorization to step-up without attempting recovery', async () => {
    const sealedRecord = buildEmailOtpSealedRecord({
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 0,
    });
    const worker = new RecoveryWorkerFixture({
      prior: activeMetadata(),
      substitutePublicKey: false,
    });
    const activation = new RecoveryActivationHarness(null);

    const result = await recoverEmailOtpEd25519YaoFromSealedSessionV1({
      subject: {
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        signerSlot: 1,
        thresholdSessionId: THRESHOLD_SESSION_ID,
      },
      expectedMaterialActivation: publicCapabilityReference().materialActivation,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      ports: {
        readExactEd25519SealedSession: async () => sealedRecord,
        readActiveWalletSessionAuthorization: readActiveEmailOtpWalletSessionAuthorization,
        workerContext: worker.context(),
        resolveActiveCapability: activation.resolve.bind(activation),
        activateCapability: activation.activate.bind(activation),
        withThresholdEd25519CommitQueue: runEd25519CommitQueueTask,
        persistRecoveredSession: persistRecoveredSessionForTest,
        fetch: unexpectedWarmBootstrapFetch,
        nowMs: Date.now,
      },
    });

    expect(result).toEqual({
      kind: 'reauth_required',
      reason: 'sealed_session_exhausted',
    });
    expect(worker.operations).toEqual([]);
    expect(activation.activateCalls).toBe(0);
  });

  test('routes expired Email OTP authorization to step-up without attempting Yao recovery', async () => {
    const nowMs = Date.now();
    const sealedRecord = buildEmailOtpSealedRecord({
      expiresAtMs: nowMs,
      remainingUses: 3,
    });
    const worker = new RecoveryWorkerFixture({
      prior: activeMetadata(),
      substitutePublicKey: false,
    });
    const activation = new RecoveryActivationHarness(null);

    const result = await recoverEmailOtpEd25519YaoFromSealedSessionV1({
      subject: {
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        signerSlot: 1,
        thresholdSessionId: THRESHOLD_SESSION_ID,
      },
      expectedMaterialActivation: publicCapabilityReference().materialActivation,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      ports: {
        readExactEd25519SealedSession: async () => sealedRecord,
        readActiveWalletSessionAuthorization: readActiveEmailOtpWalletSessionAuthorization,
        workerContext: worker.context(),
        resolveActiveCapability: activation.resolve.bind(activation),
        activateCapability: activation.activate.bind(activation),
        withThresholdEd25519CommitQueue: runEd25519CommitQueueTask,
        persistRecoveredSession: persistRecoveredSessionForTest,
        fetch: unexpectedWarmBootstrapFetch,
        nowMs: () => nowMs,
      },
    });

    expect(result).toEqual({
      kind: 'reauth_required',
      reason: 'sealed_session_expired',
    });
    expect(worker.operations).toEqual([]);
    expect(activation.activateCalls).toBe(0);
  });

  test('resolves an exact export context after refresh from exhausted authorization', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const thresholdExpiresAtMs = expiresAtMs + 60_000;
    const sealedRecord = buildEmailOtpSealedRecord({ expiresAtMs, remainingUses: 0 });
    const prior = activeMetadata();
    let bootstrapRequests = 0;

    const context = await resolveEmailOtpEd25519YaoExportContextV1({
      subject: exportLaneIdentity(),
      expectedMaterialActivation: publicCapabilityReference().materialActivation,
      relayerUrl: RELAYER_URL,
      ports: {
        readExactEd25519SealedSession: async (locator) => {
          expect(locator).toEqual({
            kind: 'ed25519_durable_material',
            authMethod: 'email_otp',
            materialActivation: publicCapabilityReference().materialActivation,
          });
          return sealedRecord;
        },
        readActiveWalletSessionAuthorization: readActiveEmailOtpWalletSessionAuthorization,
        fetch: async () => {
          bootstrapRequests += 1;
          return new Response(
            JSON.stringify(
              await warmRecoveryBootstrapResponse({ expiresAtMs, thresholdExpiresAtMs, prior }),
            ),
            {
              status: 200,
              headers: { 'Content-Type': 'application/json' },
            },
          );
        },
      },
    });

    expect(bootstrapRequests).toBe(1);
    expect(context).toMatchObject({
      kind: 'email_otp_ed25519_yao_export_context_v1',
      lane: {
        thresholdSessionId: THRESHOLD_SESSION_ID,
        walletSessionId: WALLET_SESSION_ID,
        quotaId: WALLET_SESSION_QUOTA_ID,
      },
      authorization: {
        walletSessionJwt: walletSessionJwt('sealed-refresh'),
      },
      material: {
        materialActivation: publicCapabilityReference().materialActivation,
        capability: {
        lifecycle: {
          lifecycleId: prior.scope.lifecycle_id,
          thresholdSessionId: THRESHOLD_SESSION_ID,
        },
        },
      },
    });
  });

  test('rejects a sealed export record whose full material activation differs from the canonical locator', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const sealedRecord = buildEmailOtpSealedRecord({ expiresAtMs, remainingUses: 0 });
    const canonicalActivation = publicCapabilityReference().materialActivation;
    const supersededActivation = unwrapDomainId(
      parseMpcMaterialActivationRef({
        ...canonicalActivation,
        lifecycleBinding: 'superseded-export-lifecycle-binding',
      }),
    );
    let authorizationReads = 0;
    let bootstrapRequests = 0;

    await expect(
      resolveEmailOtpEd25519YaoExportContextV1({
        subject: exportLaneIdentity(),
        expectedMaterialActivation: supersededActivation,
        relayerUrl: RELAYER_URL,
        ports: {
          readExactEd25519SealedSession: async () => sealedRecord,
          readActiveWalletSessionAuthorization: async () => {
            authorizationReads += 1;
            return await readActiveEmailOtpWalletSessionAuthorization();
          },
          fetch: async () => {
            bootstrapRequests += 1;
            throw new Error('unexpected bootstrap request');
          },
        },
      }),
    ).rejects.toThrow('exact durable Email OTP Yao context is unavailable');
    expect(authorizationReads).toBe(0);
    expect(bootstrapRequests).toBe(0);
  });

  test('cold recovery resolves the exact durable public signer and capability projections', async () => {
    const user = emailOtpUser();
    const reference = publicCapabilityReference();
    const fixture = new ColdRecoveryResolutionFixture({
      users: [user],
      references: [reference],
    });

    const resolved = await resolveEmailOtpEd25519YaoColdRecoveryV1(fixture, {
      walletId: WALLET_ID,
      walletSessionUserId: PROVIDER_SUBJECT,
    });

    expect(resolved).toEqual({
      identity: reference,
      user,
      providerSubject: PROVIDER_SUBJECT,
    });
  });

  test('cold recovery fails closed when its durable public capability reference is missing', async () => {
    const fixture = new ColdRecoveryResolutionFixture({
      users: [emailOtpUser()],
      references: [],
    });

    await expect(
      resolveEmailOtpEd25519YaoColdRecoveryV1(fixture, {
        walletId: WALLET_ID,
        walletSessionUserId: PROVIDER_SUBJECT,
      }),
    ).rejects.toThrow('one exact durable public capability reference');
  });

  test('cold activation publishes a fresh activation for the durable signer', async () => {
    const priorMetadata = activeMetadata();
    const worker = new RecoveryWorkerFixture({
      prior: priorMetadata,
      substitutePublicKey: false,
      requireFreshMaterialActivation: true,
    });
    const activation = new RecoveryActivationHarness(null);
    const prepared = prepareColdEmailOtpEd25519YaoRecoveryV1({
      identity: publicCapabilityReference(),
      thresholdSessionId: unwrapDomainId(parseThresholdEd25519SessionId(THRESHOLD_SESSION_ID)),
      signerSlot: 1,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      providerSubject: PROVIDER_SUBJECT,
      emailHashHex: EMAIL_HASH_HEX,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      remainingUses: 3,
      resolveActiveCapability: resolveNoActiveCapability,
    });

    const result = await activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
      prepared,
      bootstrap: recoveryBootstrap({
        remainingUses: 3,
        prior: priorMetadata,
        substitutePublicKey: false,
        substituteParticipantIds: false,
        substituteSignerSetId: false,
        materialActivation: RECOVERY_MATERIAL_ACTIVATION,
      }),
      pendingFactorHandle: pendingFactorHandle(),
      workerContext: worker.context(),
      activateCapability: activation.activate.bind(activation),
    });

    expect(worker.operations).toEqual(['bindEmailOtpEd25519YaoRoot', 'recoverEmailOtpEd25519Yao']);
    expect(activation.activateCalls).toBe(1);
    expect(result.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
    expect(result.walletSessionState.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
    expect(result.walletSessionState.walletSessionId).toBe(WALLET_SESSION_ID);
    expect(result.walletSessionState.quotaId).toBe(WALLET_SESSION_QUOTA_ID);
    expect(result.walletSessionState.remainingUses).toBe(3);
    expect(result.walletSessionState.signingLane.identity.signer.signerSlot).toBe(
      result.material.activeClient.metadata().applicationBinding.key_creation_signer_slot,
    );
    expect(result.walletSessionState.signingLane.storageSource).toBe('email_otp');
    expect(result.material.activeClient.metadata().registeredPublicKey).toEqual(REGISTERED_PUBLIC_KEY);
    const recoveredActivation = nearEd25519YaoMaterialActivationFromMetadata(
      result.material.activeClient.metadata(),
    );
    expect(mpcMaterialActivationRefsEqual(recoveredActivation, priorMetadata.materialActivation))
      .toBe(false);
  });

  test('cold activation rejects a Wallet Session bearer bound to another quota', async () => {
    const priorMetadata = activeMetadata();
    const worker = new RecoveryWorkerFixture({
      prior: priorMetadata,
      substitutePublicKey: false,
    });
    const activation = new RecoveryActivationHarness(null);
    const prepared = prepareColdEmailOtpEd25519YaoRecoveryV1({
      identity: publicCapabilityReference(),
      thresholdSessionId: unwrapDomainId(
        parseThresholdEd25519SessionId(THRESHOLD_SESSION_ID),
      ),
      signerSlot: 1,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      providerSubject: PROVIDER_SUBJECT,
      emailHashHex: EMAIL_HASH_HEX,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      authPolicy: 'session',
      remainingUses: 3,
      resolveActiveCapability: resolveNoActiveCapability,
    });

    await expect(
      activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
        prepared,
        bootstrap: recoveryBootstrap({
          remainingUses: 3,
          prior: priorMetadata,
          substitutePublicKey: false,
          substituteParticipantIds: false,
          substituteSignerSetId: false,
          walletSessionJwt: walletSessionJwt('wrong-quota', 'substituted-wallet-session-quota'),
        }),
        pendingFactorHandle: pendingFactorHandle(),
        workerContext: worker.context(),
        activateCapability: activation.activate.bind(activation),
      }),
    ).rejects.toThrow('wallet_binding_mismatch');
    expect(activation.activateCalls).toBe(0);
  });

  test('cold activation disposes its pending factor when the public key is substituted', async () => {
    const priorMetadata = activeMetadata();
    const worker = new RecoveryWorkerFixture({
      prior: priorMetadata,
      substitutePublicKey: true,
    });
    const activation = new RecoveryActivationHarness(null);
    const pendingFactor = pendingFactorHandle();
    const prepared = prepareColdEmailOtpEd25519YaoRecoveryV1({
      identity: publicCapabilityReference(),
      thresholdSessionId: unwrapDomainId(parseThresholdEd25519SessionId(THRESHOLD_SESSION_ID)),
      signerSlot: 1,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      providerSubject: PROVIDER_SUBJECT,
      emailHashHex: EMAIL_HASH_HEX,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      remainingUses: 3,
      resolveActiveCapability: resolveNoActiveCapability,
    });

    await expect(
      activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
        prepared,
        bootstrap: recoveryBootstrap({
          remainingUses: 3,
          prior: priorMetadata,
          substitutePublicKey: true,
          substituteParticipantIds: false,
          substituteSignerSetId: false,
        }),
        pendingFactorHandle: pendingFactor,
        workerContext: worker.context(),
        activateCapability: activation.activate.bind(activation),
      }),
    ).rejects.toThrow('cold recovery changed the registered wallet identity');

    expect(worker.operations).toEqual(['disposeEmailOtpEd25519YaoPendingFactor']);
    expect(worker.disposedPendingFactor).toEqual(pendingFactor);
    expect(activation.activateCalls).toBe(0);
  });

  test('cold activation disposes its pending factor when the signer set is substituted', async () => {
    const priorMetadata = activeMetadata();
    const worker = new RecoveryWorkerFixture({
      prior: priorMetadata,
      substitutePublicKey: false,
    });
    const activation = new RecoveryActivationHarness(null);
    const pendingFactor = pendingFactorHandle();
    const prepared = prepareColdEmailOtpEd25519YaoRecoveryV1({
      identity: publicCapabilityReference(),
      thresholdSessionId: unwrapDomainId(parseThresholdEd25519SessionId(THRESHOLD_SESSION_ID)),
      signerSlot: 1,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      providerSubject: PROVIDER_SUBJECT,
      emailHashHex: EMAIL_HASH_HEX,
      rpId: RP_ID,
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      remainingUses: 3,
      resolveActiveCapability: resolveNoActiveCapability,
    });

    await expect(
      activateColdEmailOtpEd25519YaoUnlockedRecoveryV1({
        prepared,
        bootstrap: recoveryBootstrap({
          remainingUses: 3,
          prior: priorMetadata,
          substitutePublicKey: false,
          substituteParticipantIds: false,
          substituteSignerSetId: true,
        }),
        pendingFactorHandle: pendingFactor,
        workerContext: worker.context(),
        activateCapability: activation.activate.bind(activation),
      }),
    ).rejects.toThrow('cold recovery changed the registered wallet identity');

    expect(worker.operations).toEqual(['disposeEmailOtpEd25519YaoPendingFactor']);
    expect(worker.disposedPendingFactor).toEqual(pendingFactor);
    expect(activation.activateCalls).toBe(0);
  });

  test('worker helper disposes its pending factor after pre-bind continuity failure', async () => {
    const prior = activeMetadata();
    const worker = new RecoveryWorkerFixture({ prior, substitutePublicKey: true });

    await expect(
      recoverEmailOtpEd25519YaoWorkerClientV1({
        workerContext: worker.context(),
        pendingFactorHandle: {
          kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
          handleId: 'pending-factor-continuity-failure',
          purpose: 'recovery',
          expiresAtMs: Date.now() + 60_000,
        },
        bootstrap: recoveryBootstrap({
          remainingUses: 3,
          prior,
          substitutePublicKey: true,
          substituteParticipantIds: false,
          substituteSignerSetId: false,
        }),
        expectedPriorMetadata: prior,
        providerSubject: PROVIDER_SUBJECT,
        registrationAuthorityId: 'email-otp-authority-1',
        routerOrigin: RELAYER_URL,
      }),
    ).rejects.toThrow('bootstrap changed the active capability');

    expect(worker.operations).toEqual(['disposeEmailOtpEd25519YaoPendingFactor']);
  });

  test('worker helper disposes its bound root after recovery dispatch failure', async () => {
    const prior = activeMetadata();
    const worker = new RecoveryWorkerFixture({
      prior,
      substitutePublicKey: false,
      failRecoveryDispatch: true,
    });

    await expect(
      recoverEmailOtpEd25519YaoWorkerClientV1({
        workerContext: worker.context(),
        pendingFactorHandle: {
          kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
          handleId: 'pending-factor-dispatch-failure',
          purpose: 'recovery',
          expiresAtMs: Date.now() + 60_000,
        },
        bootstrap: recoveryBootstrap({
          remainingUses: 3,
          prior,
          substitutePublicKey: false,
          substituteParticipantIds: false,
          substituteSignerSetId: false,
        }),
        expectedPriorMetadata: prior,
        providerSubject: PROVIDER_SUBJECT,
        registrationAuthorityId: 'email-otp-authority-1',
        routerOrigin: RELAYER_URL,
      }),
    ).rejects.toThrow('injected recovery dispatch failure');

    expect(worker.operations).toEqual([
      'bindEmailOtpEd25519YaoRoot',
      'recoverEmailOtpEd25519Yao',
      'disposeEmailOtpEd25519YaoRoot',
    ]);
  });

  test('worker helper preserves the primary failure when the consumed root is already absent', async () => {
    const prior = activeMetadata();
    const worker = new RecoveryWorkerFixture({
      prior,
      substitutePublicKey: false,
      failRecoveryDispatch: true,
      disposeBoundRootResult: false,
    });

    await expect(
      recoverEmailOtpEd25519YaoWorkerClientV1({
        workerContext: worker.context(),
        pendingFactorHandle: {
          kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
          handleId: 'pending-factor-consumed-root',
          purpose: 'recovery',
          expiresAtMs: Date.now() + 60_000,
        },
        bootstrap: recoveryBootstrap({
          remainingUses: 3,
          prior,
          substitutePublicKey: false,
          substituteParticipantIds: false,
          substituteSignerSetId: false,
        }),
        expectedPriorMetadata: prior,
        providerSubject: PROVIDER_SUBJECT,
        registrationAuthorityId: 'email-otp-authority-1',
        routerOrigin: RELAYER_URL,
      }),
    ).rejects.toThrow('injected recovery dispatch failure');

    expect(worker.operations).toEqual([
      'bindEmailOtpEd25519YaoRoot',
      'recoverEmailOtpEd25519Yao',
      'disposeEmailOtpEd25519YaoRoot',
    ]);
  });
});
