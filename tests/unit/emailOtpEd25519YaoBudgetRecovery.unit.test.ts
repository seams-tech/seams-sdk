import { expect, test } from '@playwright/test';
import type { ClientUserData } from '../../packages/sdk-web/src/core/accountData/near/nearAccountData.types';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import type { NearEd25519YaoSigningCapability } from '../../packages/sdk-web/src/core/signingEngine/interfaces/near';
import {
  activateColdEmailOtpEd25519YaoUnlockedRecoveryV1,
  prepareColdEmailOtpEd25519YaoRecoveryV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoBudgetRecovery';
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
import {
  buildCurrentSealedSessionRecord,
  type CurrentEd25519SealedSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  recoverEmailOtpEd25519YaoFromSealedSessionV1,
  resolveEmailOtpEd25519YaoExportContextV1,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoSealedRecovery';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  parseThresholdEd25519SessionId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { buildActiveWalletSessionAuthorizationProjection } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { resolveThresholdEd25519CommitQueueKey } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/commitQueue';
import { exactEd25519SigningLaneIdentity } from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildImplicitNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
} from '../../packages/shared-ts/src/utils/walletCapabilityBindings';
import { parseImplicitNearAccountId } from '../../packages/shared-ts/src/utils/near';

const WALLET_ID = walletIdFromString('email-otp-ed25519-budget.testnet');
const NEAR_ACCOUNT_ID = toAccountId('ab'.repeat(32));
const NEAR_ED25519_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString(
  'email-otp-ed25519-budget.testnet',
);
const THRESHOLD_SESSION_ID = 'email-otp-ed25519-threshold-session';
const WALLET_SESSION_ID = unwrapDomainId(parseWalletSessionId('email-otp-ed25519-wallet-session'));
const WALLET_SESSION_QUOTA_ID = unwrapDomainId(
  parseMpcWalletSigningQuotaId('email-otp-ed25519-wallet-session-quota'),
);
const SIGNING_GRANT_ID = 'email-otp-ed25519-signing-grant';
const RECOVERED_SIGNING_GRANT_ID = 'email-otp-ed25519-recovered-signing-grant';
const PROVIDER_SUBJECT = 'google:email-otp-ed25519-budget-subject';
const RELAYER_URL = 'https://relay.example.test';
const SIGNING_WORKER_ID = 'email-otp-ed25519-signing-worker';
const SIGNING_ROOT_ID = 'project-email-otp-ed25519:dev';
const PARTICIPANT_IDS = [1, 2] as const;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-email-otp-ed25519',
  projectId: 'project-email-otp-ed25519',
  envId: 'dev',
  signingRootVersion: 'root-v1',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: SIGNING_WORKER_ID,
} as const;
const REGISTERED_PUBLIC_KEY = new Uint8Array(32).fill(7);
const PRIOR_CAPABILITY_BINDING = new Array<number>(32).fill(1);

function exportLaneIdentity() {
  const account = parseImplicitNearAccountId(NEAR_ACCOUNT_ID);
  if (!account.ok) throw new Error(account.message);
  return exactEd25519SigningLaneIdentity({
    signer: buildNearEd25519SignerBinding({
      account: buildImplicitNearAccountBinding({
        wallet: buildWalletIdentity({ walletId: WALLET_ID }),
        nearAccountId: account.value,
      }),
      nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
      signerSlot: 1,
    }),
    auth: { kind: 'email_otp', providerSubjectId: PROVIDER_SUBJECT },
    signingGrantId: SIGNING_GRANT_ID,
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

function walletSessionJwt(version: string, signingGrantId = SIGNING_GRANT_ID): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u({
    kind: 'router_ab_ed25519_wallet_session_v1',
    sub: String(WALLET_ID),
    walletId: String(WALLET_ID),
    nearAccountId: String(NEAR_ACCOUNT_ID),
    nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
    walletSessionId: WALLET_SESSION_ID,
    quotaId: WALLET_SESSION_QUOTA_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId,
    relayerKeyId: SIGNING_WORKER_ID,
    rpId: 'localhost',
    participantIds: [...PARTICIPANT_IDS],
    version,
  })}.fixture`;
}

async function readActiveEmailOtpWalletSessionAuthorization() {
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: PROVIDER_SUBJECT,
    emailHashHex: '11'.repeat(32),
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
      wallet_session_id: THRESHOLD_SESSION_ID,
      signer_set_id: 'near_ed25519:slot:1',
      signing_worker_id: SIGNING_WORKER_ID,
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
  };
}

function recoveryBootstrap(args: {
  remainingUses: number;
  prior: RouterAbEd25519YaoActiveClientMetadataV1;
  substitutePublicKey: boolean;
  substituteParticipantIds: boolean;
  substituteSignerSetId: boolean;
  walletSessionJwt?: string;
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
        args.walletSessionJwt ?? walletSessionJwt('recovered', RECOVERED_SIGNING_GRANT_ID),
      walletId: WALLET_ID,
      nearAccountId: String(NEAR_ACCOUNT_ID),
      nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
      authorityScope: {
        kind: 'email_otp',
        provider: 'google',
        providerUserId: PROVIDER_SUBJECT,
      },
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingGrantId: RECOVERED_SIGNING_GRANT_ID,
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

  constructor(args: {
    prior: RouterAbEd25519YaoActiveClientMetadataV1;
    substitutePublicKey: boolean;
    substituteParticipantIds?: boolean;
    substituteSignerSetId?: boolean;
    failRecoveryDispatch?: boolean;
    disposeBoundRootResult?: boolean;
  }) {
    this.prior = args.prior;
    this.substitutePublicKey = args.substitutePublicKey;
    this.substituteParticipantIds = args.substituteParticipantIds === true;
    this.substituteSignerSetId = args.substituteSignerSetId === true;
    this.failRecoveryDispatch = args.failRecoveryDispatch === true;
    this.disposeBoundRootResult = args.disposeBoundRootResult !== false;
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
          ed25519YaoSession: {
            kind: 'exact_local_material_session_v1',
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
        if (request.payload.material.kind === 'ed25519_yao_exact_local_session') {
          throw new Error(
            '[SigningEngine][near] Email OTP local Ed25519 material is unavailable; explicit recovery or device linking is required',
          );
        }
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
  private readonly previous: NearEd25519YaoSigningCapability | null;
  activated: NearEd25519YaoSigningCapability | null = null;
  activateCalls = 0;

  constructor(previous: NearEd25519YaoSigningCapability | null) {
    this.previous = previous;
  }

  resolve(scope: Ed25519YaoActiveClientLookupScopeV1): NearEd25519YaoSigningCapability | null {
    return this.previous && scope.walletId === WALLET_ID && scope.nearAccountId === NEAR_ACCOUNT_ID
      ? this.previous
      : null;
  }

  async activate(
    capability: NearEd25519YaoSigningCapability,
  ): Promise<Ed25519YaoActiveClientIdentityV1> {
    this.activateCalls += 1;
    this.activated = capability;
    return {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
        capability.activeClient.metadata(),
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

function resolveNoActiveCapability(): NearEd25519YaoSigningCapability | null {
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
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: 'email_otp',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    thresholdSessionIds: { ed25519: THRESHOLD_SESSION_ID },
    walletId: String(WALLET_ID),
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    relayerUrl: RELAYER_URL,
    sealedSecretB64u: 'sealed-email-otp-ed25519-factor',
    keyVersion: 'seal-v1',
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    issuedAtMs: Date.now() - 1_000,
    expiresAtMs: args.expiresAtMs,
    remainingUses: args.remainingUses,
    updatedAtMs: Date.now(),
    ed25519Restore: {
      nearAccountId: String(NEAR_ACCOUNT_ID),
      nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
      rpId: 'localhost',
      provider: 'google',
      providerSubjectId: PROVIDER_SUBJECT,
      emailHashHex: '11'.repeat(32),
      materialActivation:
        args.materialActivation ?? publicCapabilityReference().materialActivation,
      relayerKeyId: SIGNING_WORKER_ID,
      participantIds: [...PARTICIPANT_IDS],
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signerSlot: 1,
      routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    },
  });
  if (!record || record.curve !== 'ed25519') {
    throw new Error('expected Email OTP Ed25519 sealed record');
  }
  return record;
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
    emailHashHex: '11'.repeat(32),
  });
  return {
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
    walletId: String(WALLET_ID),
    nearAccountId: String(NEAR_ACCOUNT_ID),
    nearEd25519SigningKeyId: String(NEAR_ED25519_SIGNING_KEY_ID),
    signerSlot: 1,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
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

test.describe('Email OTP Ed25519 Yao budget recovery', () => {
  test('silently recovers a valid sealed Email OTP grant after page refresh', async () => {
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
      rpId: 'localhost',
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      ports: {
        readExactSealedSession: async () => sealedRecord,
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
      rpId: 'localhost',
      provider: 'google',
      providerSubjectId: PROVIDER_SUBJECT,
      emailHashHex: '11'.repeat(32),
    });
    expect(publicationInput?.capability.walletSessionState.thresholdSessionId).toBe(
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
        rpId: 'localhost',
        relayerUrl: RELAYER_URL,
        authPolicy: 'session',
        ports: {
          readExactSealedSession: async () => {
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

  test('routes an exhausted sealed Email OTP grant to step-up without attempting recovery', async () => {
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
      rpId: 'localhost',
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      ports: {
        readExactSealedSession: async () => sealedRecord,
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

  test('routes an expired sealed Email OTP grant to step-up without attempting Yao recovery', async () => {
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
      rpId: 'localhost',
      relayerUrl: RELAYER_URL,
      authPolicy: 'session',
      ports: {
        readExactSealedSession: async () => sealedRecord,
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

  test('resolves an exact export context after refresh from an exhausted signing grant', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const thresholdExpiresAtMs = expiresAtMs + 60_000;
    const sealedRecord = buildEmailOtpSealedRecord({ expiresAtMs, remainingUses: 0 });
    const prior = activeMetadata();
    let bootstrapRequests = 0;

    const context = await resolveEmailOtpEd25519YaoExportContextV1({
      subject: exportLaneIdentity(),
      relayerUrl: RELAYER_URL,
      ports: {
        readExactSealedSession: async () => sealedRecord,
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
        signingGrantId: SIGNING_GRANT_ID,
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
    });
    const activation = new RecoveryActivationHarness(null);
    const prepared = prepareColdEmailOtpEd25519YaoRecoveryV1({
      identity: publicCapabilityReference(),
      thresholdSessionId: unwrapDomainId(parseThresholdEd25519SessionId(THRESHOLD_SESSION_ID)),
      signerSlot: 1,
      expectedOperationalPublicKey: emailOtpUser().operationalPublicKey,
      providerSubject: PROVIDER_SUBJECT,
      emailHashHex: '11'.repeat(32),
      rpId: 'localhost',
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
      }),
      pendingFactorHandle: pendingFactorHandle(),
      workerContext: worker.context(),
      activateCapability: activation.activate.bind(activation),
    });

    expect(worker.operations).toEqual(['bindEmailOtpEd25519YaoRoot', 'recoverEmailOtpEd25519Yao']);
    expect(activation.activateCalls).toBe(1);
    expect(result.sessionId).toBe(THRESHOLD_SESSION_ID);
    expect(result.walletSessionState.thresholdSessionId).toBe(THRESHOLD_SESSION_ID);
    expect(result.walletSessionState.signingGrantId).toBe(RECOVERED_SIGNING_GRANT_ID);
    expect(result.walletSessionState.remainingUses).toBe(3);
    expect(result.walletSessionState.signingLane.identity.signer.signerSlot).toBe(
      result.activeClient.metadata().applicationBinding.key_creation_signer_slot,
    );
    expect(result.walletSessionState.signingLane.storageSource).toBe('email_otp');
    expect(result.activeClient.metadata().registeredPublicKey).toEqual(REGISTERED_PUBLIC_KEY);
  });

  test('cold activation rejects a Wallet Session bearer bound to another grant', async () => {
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
      emailHashHex: '11'.repeat(32),
      rpId: 'localhost',
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
          walletSessionJwt: walletSessionJwt('wrong-grant', 'substituted-signing-grant'),
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
      emailHashHex: '11'.repeat(32),
      rpId: 'localhost',
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
      emailHashHex: '11'.repeat(32),
      rpId: 'localhost',
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
