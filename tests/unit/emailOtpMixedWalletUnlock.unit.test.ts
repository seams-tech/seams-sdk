import { expect, test } from '@playwright/test';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../../packages/sdk-web/src/core/config/defaultConfigs';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  loginWithEmailOtpEcdsaCapability,
  prepareEmailOtpEcdsaExportCapability,
  type EmailOtpEcdsaLoginPorts,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin';
import type { EmailOtpEcdsaPublicationPorts } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication';
import { unlockEmailOtpMixedWallet } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/walletUnlock';
import { toAuthorizingSigningGrantId } from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { WorkerOperationContext } from '../../packages/sdk-web/src/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerOperationMap,
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '../../packages/sdk-web/src/core/signingEngine/workerManager/workerTypes';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import {
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import { computeEcdsaDerivationRoleLocalThresholdKeyId } from '../../packages/shared-ts/src/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands';
import {
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '../../packages/shared-ts/src/utils/emailOtpDomain';

type UnlockResult = EmailOtpWorkerOperationMap['loginWithEmailOtpWallet']['result'];

type RecordedWorkerRequest = {
  readonly type: string;
  readonly timeoutMs: number | undefined;
  readonly payload: Record<string, unknown>;
  readonly onEvent: unknown;
};

type RecordedWorkerOperationArgs = {
  readonly kind: SignerWorkerKind;
  readonly request: {
    readonly type: string;
    readonly timeoutMs?: number;
    readonly payload: unknown;
    readonly onEvent?: unknown;
  };
};

const WALLET_ID = toWalletId('mixed-email-otp-wallet.testnet');
const CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'evm-11155111',
} as const;
const TEMPO_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'test',
  signingRootVersion: 'root-v1',
} as const;
const ECDSA_HANDLE_BINDING: EmailOtpEcdsaSessionBootstrapHandleBinding = {
  evmFamilySigningKeySlotId: 'evm-family-primary',
  authSubjectId: 'google:mixed-subject',
  operation: 'wallet_unlock',
  chainTarget: CHAIN_TARGET,
};
const ECDSA_ROOT_HANDLE: EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'ecdsa-root-session',
  walletId: String(WALLET_ID),
  evmFamilySigningKeySlotId: ECDSA_HANDLE_BINDING.evmFamilySigningKeySlotId,
  authSubjectId: ECDSA_HANDLE_BINDING.authSubjectId,
  action: 'threshold_ecdsa_bootstrap',
  operation: 'wallet_unlock',
  chainTarget: CHAIN_TARGET,
};
const PENDING_FACTOR_HANDLE = {
  kind: 'email_otp_ed25519_yao_pending_factor_handle_v1',
  handleId: 'pending-factor-session',
  purpose: 'recovery',
  expiresAtMs: 1_800_000_000_000,
} as const;
const RECOVERY = {
  challengeId: 'challenge-1',
  enrollmentSealKeyVersion: 'email-otp-v1',
  unlockChallengeId: 'unlock-challenge-1',
  unlockChallengeB64u: 'unlock-challenge-b64u',
  clientUnlockPublicKeyB64u: 'client-unlock-public-key',
  unlockSignatureB64u: 'unlock-signature',
} as const;

const NEAR_ACCOUNT_ID = 'ab'.repeat(32);
const NEAR_ED25519_SIGNING_KEY_ID = 'near-key-primary';
const THRESHOLD_SESSION_ID = 'threshold-session-1';
const SIGNING_GRANT_ID = 'signing-grant-1';
const PARTICIPANT_IDS = [1, 2] as const;
const REMAINING_USES = 3;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-1',
} as const;

const ED25519_RECOVERY_BOOTSTRAP: EmailOtpEd25519YaoRecoveryBootstrapV1 = {
  kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
  session: {
    sessionKind: 'jwt',
    walletSessionJwt: 'header.payload.signature',
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
    authorityScope: {
      kind: 'email_otp',
      provider: 'google',
      providerUserId: 'google:mixed-subject',
    },
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
    expiresAtMs: 1_800_000_000_000,
    participantIds: PARTICIPANT_IDS,
    remainingUses: REMAINING_USES,
    signingRootId: 'project-test:test',
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
  },
  capability: {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    activeCapabilityBinding: new Array<number>(32).fill(1),
    registeredPublicKey: new Array<number>(32).fill(2),
    nearAccountId: NEAR_ACCOUNT_ID,
    applicationBinding: {
      wallet_id: String(WALLET_ID),
      near_ed25519_signing_key_id: NEAR_ED25519_SIGNING_KEY_ID,
      signing_root_id: 'project-test:test',
      key_creation_signer_slot: 1,
    },
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    participantIds: PARTICIPANT_IDS,
    lifecycle: {
      lifecycleId: 'email-otp-mixed-wallet-lifecycle',
      rootShareEpoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
      accountId: String(WALLET_ID),
      walletSessionId: THRESHOLD_SESSION_ID,
      signerSetId: 'near-primary',
      signingWorkerId: 'signing-worker-1',
    },
    stateEpoch: 1,
  },
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function recordWorkerRequest(
  request: RecordedWorkerOperationArgs['request'],
): RecordedWorkerRequest {
  return {
    type: request.type,
    timeoutMs: request.timeoutMs,
    payload: requireRecord(request.payload, `${request.type} payload`),
    onEvent: request.onEvent,
  };
}

class MixedUnlockWorkerFixture implements WorkerOperationContext {
  readonly requests: RecordedWorkerRequest[] = [];
  private readonly result: UnlockResult;

  constructor(result: UnlockResult) {
    this.result = result;
  }

  async requestWorkerOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
  async requestWorkerOperation(args: RecordedWorkerOperationArgs): Promise<unknown> {
    if (args.kind !== 'emailOtp') throw new Error('expected emailOtp worker');
    const request = recordWorkerRequest(args.request);
    if (request.type !== 'loginWithEmailOtpWallet') {
      throw new Error(`unexpected worker operation ${request.type}`);
    }
    this.requests.push(request);
    return this.result;
  }
}

class MixedLoginFailureWorkerFixture implements WorkerOperationContext {
  readonly operations: string[] = [];
  disposedPendingFactorHandle: unknown = null;
  private readonly clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;

  constructor(clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload) {
    this.clientRootShareHandle = clientRootShareHandle;
  }

  async requestWorkerOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
  async requestWorkerOperation(args: RecordedWorkerOperationArgs): Promise<unknown> {
    if (args.kind !== 'emailOtp') throw new Error('expected emailOtp worker');
    const request = recordWorkerRequest(args.request);
    this.operations.push(request.type);
    switch (request.type) {
      case 'loginWithEmailOtpWallet':
        return {
          kind: 'ecdsa_and_ed25519_yao_recovery',
          recovery: RECOVERY,
          clientRootShareHandle: this.clientRootShareHandle,
          pendingFactorHandle: PENDING_FACTOR_HANDLE,
          ed25519YaoRecovery: ED25519_RECOVERY_BOOTSTRAP,
        };
      case 'disposeEmailOtpEd25519YaoPendingFactor':
        this.disposedPendingFactorHandle = request.payload.pendingFactorHandle;
        return { removed: true };
      default:
        throw new Error(`unexpected worker operation ${request.type}`);
    }
  }
}

class ExportHandleWorkerFixture implements WorkerOperationContext {
  readonly operations: string[] = [];
  readonly disposalPayloads: Record<string, unknown>[] = [];
  private readonly clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;

  constructor(clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload) {
    this.clientRootShareHandle = clientRootShareHandle;
  }

  async requestWorkerOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
  async requestWorkerOperation(args: RecordedWorkerOperationArgs): Promise<unknown> {
    if (args.kind !== 'emailOtp') throw new Error('expected emailOtp worker');
    const request = recordWorkerRequest(args.request);
    this.operations.push(request.type);
    switch (request.type) {
      case 'loginWithEmailOtpWallet':
        return {
          kind: 'ecdsa',
          recovery: RECOVERY,
          clientRootShareHandle: this.clientRootShareHandle,
        };
      case 'disposeEmailOtpEcdsaClientRootHandle':
        this.disposalPayloads.push(request.payload);
        return { removed: true };
      default:
        throw new Error(`unexpected worker operation ${request.type}`);
    }
  }
}

class UnreachablePublicationPorts implements EmailOtpEcdsaPublicationPorts {
  readonly configs = PASSKEY_MANAGER_DEFAULT_CONFIGS;
  private readonly workerCtx: WorkerOperationContext;

  private readonly existingRecord: ThresholdEcdsaSessionRecord;

  constructor(workerCtx: WorkerOperationContext, existingRecord: ThresholdEcdsaSessionRecord) {
    this.workerCtx = workerCtx;
    this.existingRecord = existingRecord;
  }

  getSignerWorkerContext(): WorkerOperationContext {
    return this.workerCtx;
  }

  async commitEvmFamilyThresholdEcdsaSessions(
    _args: Parameters<EmailOtpEcdsaPublicationPorts['commitEvmFamilyThresholdEcdsaSessions']>[0],
  ): Promise<never> {
    throw new Error('publication must not run after ECDSA bootstrap failure');
  }

  async registerSigningSession(
    _record: Parameters<EmailOtpEcdsaPublicationPorts['registerSigningSession']>[0],
  ): Promise<never> {
    throw new Error('session persistence must not run after ECDSA bootstrap failure');
  }

  async readExactSealedSession(
    ..._args: Parameters<EmailOtpEcdsaPublicationPorts['readExactSealedSession']>
  ): Promise<never> {
    throw new Error('sealed session reads must not run after ECDSA bootstrap failure');
  }

  readonly listThresholdEcdsaSessionRecordsForWallet: EmailOtpEcdsaPublicationPorts['listThresholdEcdsaSessionRecordsForWallet'] =
    () => [this.existingRecord];

  async listActiveEcdsaSignersForWallet(): Promise<[]> {
    return [];
  }
}

class MixedLoginPortsFixture implements EmailOtpEcdsaLoginPorts {
  readonly configs = PASSKEY_MANAGER_DEFAULT_CONFIGS;
  readonly publicationPorts: EmailOtpEcdsaPublicationPorts;
  private readonly workerCtx: WorkerOperationContext;

  ecdsaBootstrapRequest: unknown = null;

  constructor(workerCtx: WorkerOperationContext, existingRecord: ThresholdEcdsaSessionRecord) {
    this.workerCtx = workerCtx;
    this.publicationPorts = new UnreachablePublicationPorts(workerCtx, existingRecord);
  }

  getSignerWorkerContext(): WorkerOperationContext {
    return this.workerCtx;
  }

  requireRelayUrl(): string {
    return 'https://relay.example.test';
  }

  requireShamirPrimeB64u(): string {
    return 'shamir-prime';
  }

  rememberAppSessionJwt(): void {}

  async provisionThresholdEcdsaSession(request: unknown): Promise<never> {
    this.ecdsaBootstrapRequest = request;
    throw new Error('injected ECDSA bootstrap failure');
  }

  async provisionEmailOtpEcdsaExplicitExportSession(): Promise<never> {
    throw new Error('explicit export provisioning is unreachable');
  }
}

class ExportLoginPortsFixture implements EmailOtpEcdsaLoginPorts {
  readonly configs = PASSKEY_MANAGER_DEFAULT_CONFIGS;
  readonly publicationPorts: EmailOtpEcdsaPublicationPorts;
  explicitExportProvisionCalls = 0;
  private readonly workerCtx: WorkerOperationContext;
  private readonly bootstrap: ThresholdEcdsaSessionBootstrapResult;
  private readonly failProvisioning: boolean;

  constructor(args: {
    workerCtx: WorkerOperationContext;
    existingRecord: ThresholdEcdsaSessionRecord;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    failProvisioning: boolean;
  }) {
    this.workerCtx = args.workerCtx;
    this.bootstrap = args.bootstrap;
    this.failProvisioning = args.failProvisioning;
    this.publicationPorts = new UnreachablePublicationPorts(args.workerCtx, args.existingRecord);
  }

  getSignerWorkerContext(): WorkerOperationContext {
    return this.workerCtx;
  }

  requireRelayUrl(): string {
    return 'https://relay.example.test';
  }

  requireShamirPrimeB64u(): string {
    return 'shamir-prime';
  }

  rememberAppSessionJwt(): void {}

  async provisionThresholdEcdsaSession(): Promise<never> {
    throw new Error('transaction provisioning is unreachable during explicit export');
  }

  async provisionEmailOtpEcdsaExplicitExportSession(): Promise<{
    kind: 'email_otp_explicit_export_bootstrap_result';
    purpose: 'explicit_key_export';
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
  }> {
    this.explicitExportProvisionCalls += 1;
    if (this.failProvisioning) throw new Error('injected explicit export provisioning failure');
    return {
      kind: 'email_otp_explicit_export_bootstrap_result',
      purpose: 'explicit_key_export',
      bootstrap: this.bootstrap,
    };
  }
}

type ExistingEmailOtpFixture = {
  readonly record: ThresholdEcdsaSessionRecord;
  readonly bootstrap: ThresholdEcdsaSessionBootstrapResult;
};

async function makeExistingEmailOtpFixture(): Promise<ExistingEmailOtpFixture> {
  const signingRootId = `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`;
  const initial = createThresholdEcdsaBootstrapFixture({
    nearAccountId: String(WALLET_ID),
    chain: 'evm',
    signingRootId,
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    ecdsaThresholdKeyId: 'placeholder',
    roleLocalAuthMethod: 'email_otp',
    emailOtpAuthSubjectId: 'google:mixed-subject',
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  });
  const ecdsaThresholdKeyId = await computeEcdsaDerivationRoleLocalThresholdKeyId({
    walletId: String(WALLET_ID),
    evmFamilySigningKeySlotId: initial.thresholdEcdsaKeyRef.evmFamilySigningKeySlotId,
    signingRootId,
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
  });
  const fixtureBootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: String(WALLET_ID),
    chain: 'evm',
    signingRootId,
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    ecdsaThresholdKeyId,
    roleLocalAuthMethod: 'email_otp',
    emailOtpAuthSubjectId: 'google:mixed-subject',
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  });
  const fixtureBinding = fixtureBootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!fixtureBinding || fixtureBinding.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('mixed Email OTP fixture requires role-local ready material');
  }
  const durableMaterialRef = parseEcdsaRoleLocalDurableMaterialRef(
    'role-local:mixed-email-otp-fixture',
  );
  const bootstrap = {
    ...fixtureBootstrap,
    thresholdEcdsaKeyRef: {
      ...fixtureBootstrap.thresholdEcdsaKeyRef,
      backendBinding: {
        materialKind: 'role_local_worker_handle' as const,
        relayerKeyId: fixtureBinding.relayerKeyId,
        clientVerifyingShareB64u: fixtureBinding.clientVerifyingShareB64u,
        roleLocalMaterialHandle: {
          kind: 'ecdsa_role_local_worker_handle_v1' as const,
          materialHandle: parseEcdsaRoleLocalMaterialHandle(
            'role-local-live:mixed-email-otp-fixture',
          ),
          bindingDigest: parseEcdsaRoleLocalBindingDigest(
            fixtureBinding.ecdsaRoleLocalReadyRecord.publicFacts.contextBinding32B64u,
          ),
          durableMaterialRef,
        },
        publicFacts: fixtureBinding.ecdsaRoleLocalReadyRecord.publicFacts,
        authMethod: fixtureBinding.ecdsaRoleLocalReadyRecord.authMethod,
      },
    },
  };
  const record = upsertThresholdEcdsaSessionFromBootstrap(
    { recordsByLane: new Map() },
    {
      walletId: WALLET_ID,
      chainTarget: CHAIN_TARGET,
      bootstrap,
      source: 'email_otp',
      emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
        policy: 'session',
        walletId: WALLET_ID,
        emailHashHex: '11'.repeat(32),
        provider: 'google',
        providerUserId: 'google:mixed-subject',
      }),
    },
  );
  return { record, bootstrap };
}

function mixedUnlockArgs(workerCtx: WorkerOperationContext) {
  return {
    walletSession: {
      walletId: WALLET_ID,
      walletSessionUserId: 'google:mixed-subject',
    },
    relayUrl: 'https://relay.example.test',
    shamirPrimeB64u: 'shamir-prime',
    otpCode: '123456',
    challengeId: 'challenge-1',
    routePlan: {
      routeFamily: 'signing_session',
      authLane: {
        kind: 'signing_session',
        jwt: 'ed25519.wallet.session.jwt',
        thresholdSessionId: THRESHOLD_SESSION_ID,
        authorizingSigningGrantId: toAuthorizingSigningGrantId(SIGNING_GRANT_ID),
        curve: 'ed25519',
      },
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    },
    workerCtx,
    ecdsaClientRootHandleBinding: ECDSA_HANDLE_BINDING,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    providerSubject: 'google:mixed-subject',
    signerSlot: 1,
    remainingUses: REMAINING_USES,
  } as const;
}

function exportRoutePlan() {
  return {
    routeFamily: 'login',
    authLane: { kind: 'app_session', jwt: 'app.session.jwt' },
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  } as const;
}

function exportCapabilityArgs(record: ThresholdEcdsaSessionRecord) {
  return {
    walletSession: {
      walletId: WALLET_ID,
      walletSessionUserId: 'google:mixed-subject',
    },
    chainTarget: CHAIN_TARGET,
    relayUrl: 'https://relay.example.test',
    challengeId: 'challenge-1',
    otpCode: '123456',
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
    shamirPrimeB64u: 'shamir-prime',
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    routePlan: exportRoutePlan(),
    keyHandle: record.keyHandle,
    remainingUses: 1,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    emailOtpAuthPolicy: 'per_operation',
    emailOtpAuthReason: 'sign',
    emailHashHex: '11'.repeat(32),
    providerIdentity: {
      kind: 'explicit_provider_user',
      providerUserId: 'google:mixed-subject',
    },
    ed25519YaoRecovery: { kind: 'not_requested' },
  } as const;
}

function exportHandleForRecord(
  record: ThresholdEcdsaSessionRecord,
  operation: EmailOtpEcdsaSessionBootstrapHandlePayload['operation'] = 'export',
): EmailOtpEcdsaSessionBootstrapHandlePayload {
  return {
    kind: 'email_otp_worker_session_handle_v1',
    sessionId: `export-root-session-${operation}`,
    walletId: String(WALLET_ID),
    evmFamilySigningKeySlotId: record.evmFamilySigningKeySlotId,
    authSubjectId: 'google:mixed-subject',
    action: 'threshold_ecdsa_bootstrap',
    operation,
    chainTarget: CHAIN_TARGET,
  };
}

test('mixed Email OTP unlock sends one coherent worker operation and returns both materials', async () => {
  const worker = new MixedUnlockWorkerFixture({
    kind: 'ecdsa_and_ed25519_yao_recovery',
    recovery: RECOVERY,
    clientRootShareHandle: ECDSA_ROOT_HANDLE,
    pendingFactorHandle: PENDING_FACTOR_HANDLE,
    ed25519YaoRecovery: ED25519_RECOVERY_BOOTSTRAP,
  });

  const result = await unlockEmailOtpMixedWallet(mixedUnlockArgs(worker));

  expect(worker.requests).toHaveLength(1);
  expect(worker.requests[0]).toEqual({
    type: 'loginWithEmailOtpWallet',
    timeoutMs: 60_000,
    payload: {
      relayUrl: 'https://relay.example.test',
      walletId: String(WALLET_ID),
      userId: 'google:mixed-subject',
      challengeId: 'challenge-1',
      otpCode: '123456',
      shamirPrimeB64u: 'shamir-prime',
      routePlan: mixedUnlockArgs(worker).routePlan,
      otpChannel: 'email_otp',
      material: {
        kind: 'ecdsa_and_ed25519_yao_recovery',
        ecdsaClientRootHandleBinding: ECDSA_HANDLE_BINDING,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        providerSubject: 'google:mixed-subject',
        ed25519YaoRecovery: {
          kind: 'router_ab_ed25519_yao_email_otp_recovery_v1',
          signerSlot: 1,
          remainingUses: REMAINING_USES,
          orgId: RUNTIME_POLICY_SCOPE.orgId,
        },
      },
    },
    onEvent: undefined,
  });
  const material = requireRecord(worker.requests[0].payload.material, 'unlock material');
  const ed25519YaoRecovery = requireRecord(
    material.ed25519YaoRecovery,
    'Ed25519 Yao recovery material',
  );
  expect(material).not.toHaveProperty('walletSessionAuth');
  expect(ed25519YaoRecovery).not.toHaveProperty('sessionPolicy');
  expect(ed25519YaoRecovery).not.toHaveProperty('walletSessionJwt');
  expect(result).toEqual({
    kind: 'ecdsa_and_ed25519_yao_recovery',
    recovery: RECOVERY,
    clientRootShareHandle: ECDSA_ROOT_HANDLE,
    pendingFactorHandle: PENDING_FACTOR_HANDLE,
    ed25519YaoRecovery: ED25519_RECOVERY_BOOTSTRAP,
  });
});

test('mixed Email OTP unlock rejects a worker result from another material branch', async () => {
  const worker = new MixedUnlockWorkerFixture({
    kind: 'ecdsa',
    recovery: RECOVERY,
    clientRootShareHandle: ECDSA_ROOT_HANDLE,
  });

  await expect(unlockEmailOtpMixedWallet(mixedUnlockArgs(worker))).rejects.toThrow(
    'Mixed Email OTP unlock returned the wrong material branch',
  );
  expect(worker.requests).toHaveLength(1);
});

test('mixed Email OTP login disposes the pending Ed25519 factor when ECDSA bootstrap fails', async () => {
  const fixture = await makeExistingEmailOtpFixture();
  const worker = new MixedLoginFailureWorkerFixture({
    ...ECDSA_ROOT_HANDLE,
    evmFamilySigningKeySlotId: fixture.record.evmFamilySigningKeySlotId,
  });
  const ports = new MixedLoginPortsFixture(worker, fixture.record);

  await expect(
    loginWithEmailOtpEcdsaCapability(
      {
        walletSession: {
          walletId: WALLET_ID,
          walletSessionUserId: 'google:mixed-subject',
        },
        chainTarget: CHAIN_TARGET,
        relayUrl: 'https://relay.example.test',
        challengeId: 'challenge-1',
        otpCode: '123456',
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
        shamirPrimeB64u: 'shamir-prime',
        ecdsaBootstrapAuthorization: {
          kind: 'explicit_route_auth',
          routeAuth: {
            kind: 'app_session',
            jwt: 'app.session.jwt',
          },
        },
        routePlan: mixedUnlockArgs(worker).routePlan,
        remainingUses: 3,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        publicationChainTargets: [CHAIN_TARGET, TEMPO_TARGET],
        emailHashHex: '11'.repeat(32),
        providerIdentity: {
          kind: 'explicit_provider_user',
          providerUserId: 'google:mixed-subject',
        },
        ed25519YaoRecovery: {
          kind: 'requested',
          providerSubject: 'google:mixed-subject',
          signerSlot: 1,
        },
      },
      ports,
    ),
  ).rejects.toThrow('injected ECDSA bootstrap failure');

  expect(worker.operations).toEqual([
    'loginWithEmailOtpWallet',
    'disposeEmailOtpEd25519YaoPendingFactor',
  ]);
  expect(ports.ecdsaBootstrapRequest).toMatchObject({
    sessionIdentity: expect.objectContaining({ signingGrantId: SIGNING_GRANT_ID }),
    lanePolicy: expect.objectContaining({ remainingUses: REMAINING_USES }),
  });
  expect(worker.disposedPendingFactorHandle).toEqual(PENDING_FACTOR_HANDLE);
});

test('Email OTP login rejects an explicit operation mismatch before worker effects', async () => {
  const fixture = await makeExistingEmailOtpFixture();
  const worker = new ExportHandleWorkerFixture(exportHandleForRecord(fixture.record));
  const ports = new ExportLoginPortsFixture({
    workerCtx: worker,
    existingRecord: fixture.record,
    bootstrap: fixture.bootstrap,
    failProvisioning: false,
  });

  await expect(
    loginWithEmailOtpEcdsaCapability(
      {
        ...exportCapabilityArgs(fixture.record),
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      },
      ports,
    ),
  ).rejects.toThrow('Email OTP operation does not match its route plan');

  expect(worker.operations).toEqual([]);
  expect(ports.explicitExportProvisionCalls).toBe(0);
});

test('Email OTP login rejects an omitted operation with an export route before worker effects', async () => {
  const fixture = await makeExistingEmailOtpFixture();
  const worker = new ExportHandleWorkerFixture(exportHandleForRecord(fixture.record));
  const ports = new ExportLoginPortsFixture({
    workerCtx: worker,
    existingRecord: fixture.record,
    bootstrap: fixture.bootstrap,
    failProvisioning: false,
  });
  const argsWithoutOperation = {
    ...exportCapabilityArgs(fixture.record),
    operation: undefined,
  };

  await expect(loginWithEmailOtpEcdsaCapability(argsWithoutOperation, ports)).rejects.toThrow(
    'Email OTP ECDSA export must use transient export preparation',
  );

  expect(worker.operations).toEqual([]);
  expect(ports.explicitExportProvisionCalls).toBe(0);
});

test('Email OTP ECDSA export disposes its exact worker handle after successful provisioning', async () => {
  const fixture = await makeExistingEmailOtpFixture();
  const handle = exportHandleForRecord(fixture.record);
  const worker = new ExportHandleWorkerFixture(handle);
  const ports = new ExportLoginPortsFixture({
    workerCtx: worker,
    existingRecord: fixture.record,
    bootstrap: fixture.bootstrap,
    failProvisioning: false,
  });

  const result = await prepareEmailOtpEcdsaExportCapability(
    exportCapabilityArgs(fixture.record),
    ports,
  );

  expect(result.bootstrap).toBe(fixture.bootstrap);
  expect(ports.explicitExportProvisionCalls).toBe(1);
  expect(worker.operations).toEqual([
    'loginWithEmailOtpWallet',
    'disposeEmailOtpEcdsaClientRootHandle',
  ]);
  expect(worker.disposalPayloads).toEqual([{ clientRootShareHandle: handle }]);
});

test('Email OTP ECDSA export disposes its exact worker handle after provisioning fails', async () => {
  const fixture = await makeExistingEmailOtpFixture();
  const handle = exportHandleForRecord(fixture.record);
  const worker = new ExportHandleWorkerFixture(handle);
  const ports = new ExportLoginPortsFixture({
    workerCtx: worker,
    existingRecord: fixture.record,
    bootstrap: fixture.bootstrap,
    failProvisioning: true,
  });

  await expect(
    prepareEmailOtpEcdsaExportCapability(exportCapabilityArgs(fixture.record), ports),
  ).rejects.toThrow('injected explicit export provisioning failure');

  expect(ports.explicitExportProvisionCalls).toBe(1);
  expect(worker.operations).toEqual([
    'loginWithEmailOtpWallet',
    'disposeEmailOtpEcdsaClientRootHandle',
  ]);
  expect(worker.disposalPayloads).toEqual([{ clientRootShareHandle: handle }]);
});

test('Email OTP ECDSA export disposes a wrong-operation worker handle after rejecting it', async () => {
  const fixture = await makeExistingEmailOtpFixture();
  const handle = exportHandleForRecord(fixture.record, 'wallet_unlock');
  const worker = new ExportHandleWorkerFixture(handle);
  const ports = new ExportLoginPortsFixture({
    workerCtx: worker,
    existingRecord: fixture.record,
    bootstrap: fixture.bootstrap,
    failProvisioning: false,
  });

  await expect(
    prepareEmailOtpEcdsaExportCapability(exportCapabilityArgs(fixture.record), ports),
  ).rejects.toThrow('Email OTP ECDSA export requires an export worker handle');

  expect(ports.explicitExportProvisionCalls).toBe(0);
  expect(worker.operations).toEqual([
    'loginWithEmailOtpWallet',
    'disposeEmailOtpEcdsaClientRootHandle',
  ]);
  expect(worker.disposalPayloads).toEqual([{ clientRootShareHandle: handle }]);
});

test('Email OTP ECDSA export rejects a forged slot binding and still disposes the handle', async () => {
  const fixture = await makeExistingEmailOtpFixture();
  const handle = {
    ...exportHandleForRecord(fixture.record),
    evmFamilySigningKeySlotId: `${fixture.record.evmFamilySigningKeySlotId}-forged`,
  };
  const worker = new ExportHandleWorkerFixture(handle);
  const ports = new ExportLoginPortsFixture({
    workerCtx: worker,
    existingRecord: fixture.record,
    bootstrap: fixture.bootstrap,
    failProvisioning: false,
  });

  await expect(
    prepareEmailOtpEcdsaExportCapability(exportCapabilityArgs(fixture.record), ports),
  ).rejects.toThrow('Email OTP ECDSA export worker handle does not match the resolved lane');

  expect(ports.explicitExportProvisionCalls).toBe(0);
  expect(worker.operations).toEqual([
    'loginWithEmailOtpWallet',
    'disposeEmailOtpEcdsaClientRootHandle',
  ]);
  expect(worker.disposalPayloads).toEqual([{ clientRootShareHandle: handle }]);
});
