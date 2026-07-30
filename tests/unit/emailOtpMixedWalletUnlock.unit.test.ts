import { expect, test } from '@playwright/test';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
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
import { createEcdsaSessionActivationFixture } from './helpers/ecdsaBootstrap.fixtures';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '../../packages/shared-ts/src/utils/emailOtpDomain';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { parseThresholdEd25519SessionId } from '../../packages/shared-ts/src/utils/domainIds';

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
const ECDSA_HANDLE_BINDING = {
  keyHandle: 'ecdsa-key-handle',
  authSubjectId: 'google:mixed-subject',
  operation: 'wallet_unlock',
  chainTarget: CHAIN_TARGET,
} as const satisfies EmailOtpEcdsaSessionBootstrapHandleBinding;
const ECDSA_SESSION_ACTIVATION = createEcdsaSessionActivationFixture({
  walletId: String(WALLET_ID),
  chain: 'evm',
  sessionId: 'mixed-email-otp-unlock-session',
});
const ECDSA_ROOT_HANDLE: EmailOtpEcdsaSessionBootstrapHandlePayload = {
  kind: 'email_otp_worker_session_handle_v1',
  sessionId: 'ecdsa-root-session',
  walletId: String(WALLET_ID),
  keyHandle: ECDSA_HANDLE_BINDING.keyHandle,
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
const THRESHOLD_SESSION_ID = requireFixtureDomainId(
  parseThresholdEd25519SessionId('threshold-session-1'),
);
const SIGNING_GRANT_ID = 'signing-grant-1';
const PARTICIPANT_IDS = [1, 2] as const;
const REMAINING_USES = 3;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-1',
} as const;

function requireFixtureDomainId<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('mixed Email OTP fixture domain id is invalid');
  return result.value;
}

function requireFixtureString(value: string | undefined, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`mixed Email OTP fixture ${field} is required`);
  return normalized;
}

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
    walletSessionId: requireFixtureDomainId(parseWalletSessionId('mixed-email-otp-wallet-session')),
    quotaId: requireFixtureDomainId(parseMpcWalletSigningQuotaId('mixed-email-otp-quota')),
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
      thresholdSessionId: THRESHOLD_SESSION_ID,
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

function mixedUnlockArgs(workerCtx: WorkerOperationContext) {
  return {
    walletSession: {
      walletId: WALLET_ID,
      walletSessionUserId: 'google:mixed-subject',
    },
    relayUrl: 'https://relay.example.test',
    groupId: 'rfc2409-group2',
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
    nearAccountId: NEAR_ACCOUNT_ID,
    expectedOperationalPublicKey: 'ed25519:fixture-public-key',
    expectedThresholdSessionId: THRESHOLD_SESSION_ID,
    ecdsaSessionActivation: ECDSA_SESSION_ACTIVATION.request,
  } as const;
}

test('mixed Email OTP unlock sends one coherent worker operation and returns both materials', async () => {
  const worker = new MixedUnlockWorkerFixture({
    kind: 'ecdsa_and_ed25519_yao_recovery',
    operation: 'wallet_unlock',
    recovery: RECOVERY,
    clientRootShareHandle: ECDSA_ROOT_HANDLE,
    ecdsaSession: ECDSA_SESSION_ACTIVATION.response,
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
      groupId: 'rfc2409-group2',
      routePlan: mixedUnlockArgs(worker).routePlan,
      otpChannel: 'email_otp',
      material: {
        kind: 'ecdsa_and_ed25519_yao_recovery',
        ecdsaClientRootHandleBinding: ECDSA_HANDLE_BINDING,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        providerSubject: 'google:mixed-subject',
        nearAccountId: NEAR_ACCOUNT_ID,
        expectedOperationalPublicKey: 'ed25519:fixture-public-key',
        expectedThresholdSessionId: THRESHOLD_SESSION_ID,
        ecdsaSessionActivation: ECDSA_SESSION_ACTIVATION.request,
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
    operation: 'wallet_unlock',
    recovery: RECOVERY,
    clientRootShareHandle: ECDSA_ROOT_HANDLE,
    ecdsaSession: ECDSA_SESSION_ACTIVATION.response,
    pendingFactorHandle: PENDING_FACTOR_HANDLE,
    ed25519YaoRecovery: ED25519_RECOVERY_BOOTSTRAP,
  });
});

test('mixed Email OTP unlock rejects a worker result from another material branch', async () => {
  const worker = new MixedUnlockWorkerFixture({
    kind: 'ecdsa',
    operation: 'sign',
    recovery: RECOVERY,
    clientRootShareHandle: ECDSA_ROOT_HANDLE,
  });

  await expect(unlockEmailOtpMixedWallet(mixedUnlockArgs(worker))).rejects.toThrow(
    'Mixed Email OTP unlock returned the wrong material branch',
  );
  expect(worker.requests).toHaveLength(1);
});
