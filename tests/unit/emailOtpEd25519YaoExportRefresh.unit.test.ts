import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  exportEd25519YaoKeyWithFreshEmailOtp,
  type Ed25519YaoExportFlowDeps,
} from '@/core/signingEngine/flows/recovery/ed25519YaoExportFlow';
import { exactEd25519SigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { EmailOtpEd25519YaoExportSubjectV1 } from '@/core/signingEngine/session/emailOtp/ed25519YaoSealedRecovery';
import type { UserConfirmDecision } from '@/core/signingEngine/stepUpConfirmation/types';
import type { UserConfirmRequest } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import {
  buildNamedNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
} from '@shared/utils/walletCapabilityBindings';
import { parseNamedNearAccountId } from '@shared/utils/near';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { resolveEmailOtpAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

const WALLET_ID = toWalletId('email-otp-export-refresh-wallet');
const NEAR_ACCOUNT_ID = toAccountId('email-otp-export-refresh.testnet');
const NEAR_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString('email-otp-export-refresh-key');
const PROVIDER_SUBJECT_ID = 'google:email-otp-export-refresh';
const THRESHOLD_SESSION_ID = 'threshold-email-otp-export-refresh';
const SIGNING_GRANT_ID = 'grant-email-otp-export-refresh';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-email-otp-export-refresh',
  projectId: 'project-email-otp-export-refresh',
  envId: 'test',
  signingRootVersion: 'root-v1',
} as const;
const CAPABILITY = {
  kind: 'router_ab_ed25519_yao_active_capability_v1',
  activeCapabilityBinding: new Array<number>(32).fill(3),
  registeredPublicKey: new Array<number>(32).fill(4),
  nearAccountId: String(NEAR_ACCOUNT_ID),
  applicationBinding: {
    wallet_id: String(WALLET_ID),
    near_ed25519_signing_key_id: String(NEAR_SIGNING_KEY_ID),
    signing_root_id: 'project-email-otp-export-refresh:test',
    key_creation_signer_slot: 1,
  },
  runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  participantIds: [1, 2] as const,
  lifecycle: {
    lifecycleId: 'lifecycle-email-otp-export-refresh',
    rootShareEpoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
    accountId: String(WALLET_ID),
    walletSessionId: THRESHOLD_SESSION_ID,
    signerSetId: 'near-ed25519-slot-1',
    signingWorkerId: 'signing-worker-email-otp-export-refresh',
  },
  stateEpoch: 1,
} as const;

function durableEd25519AuthLane() {
  const authLane = resolveEmailOtpAuthLane({
    routeAuth: { kind: 'wallet_session', jwt: 'durable-wallet-session-jwt' },
    thresholdSessionId: THRESHOLD_SESSION_ID,
    authorizingSigningGrantId: SIGNING_GRANT_ID,
    curve: 'ed25519',
  });
  if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ed25519') {
    throw new Error('expected durable Ed25519 signing-session authority');
  }
  return authLane;
}

function buildLaneIdentity() {
  const parsedNearAccountId = parseNamedNearAccountId(NEAR_ACCOUNT_ID);
  if (!parsedNearAccountId.ok) throw new Error(parsedNearAccountId.message);
  const signer = buildNearEd25519SignerBinding({
    account: buildNamedNearAccountBinding({
      wallet: buildWalletIdentity({ walletId: WALLET_ID }),
      nearAccountId: parsedNearAccountId.value,
    }),
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    signerSlot: 1,
  });
  return exactEd25519SigningLaneIdentity({
    signer,
    auth: { kind: 'email_otp', providerSubjectId: PROVIDER_SUBJECT_ID },
    signingGrantId: SIGNING_GRANT_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
}

class EmailOtpEd25519ExportRefreshHarness {
  contextCalls = 0;
  passkeyRecoveryCalls = 0;
  exportCalls = 0;
  exportedCapability: unknown = null;

  async requestUserConfirmation(request: UserConfirmRequest): Promise<UserConfirmDecision> {
    if (this.contextCalls === 1 && this.exportCalls === 0) {
      return {
        requestId: request.requestId,
        confirmed: true,
        otpCode: '123456',
        emailOtpChallengeId: 'challenge-email-otp-export-refresh',
      };
    }
    return { requestId: request.requestId, confirmed: true };
  }

  async unexpectedPasskeyExport(): Promise<never> {
    throw new Error('Email OTP export must not enter the passkey export worker');
  }

  async initialize(): Promise<void> {}

  resolveActiveCapability(): null {
    return null;
  }

  async recoverPasskeyCapability(): Promise<never> {
    this.passkeyRecoveryCalls += 1;
    throw new Error('Email OTP export must not recover a passkey capability');
  }

  async resolvePasskeyExportContext(): Promise<never> {
    throw new Error('Email OTP export must not resolve a passkey export context');
  }

  async resolveExportContext(subject: EmailOtpEd25519YaoExportSubjectV1) {
    this.contextCalls += 1;
    expect(subject).toEqual({
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      signerSlot: 1,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingGrantId: SIGNING_GRANT_ID,
      providerSubjectId: PROVIDER_SUBJECT_ID,
    });
    return {
      kind: 'email_otp_ed25519_yao_export_context_v1' as const,
      authLane: durableEd25519AuthLane(),
      walletSessionJwt: 'durable-wallet-session-jwt',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      capability: CAPABILITY,
    };
  }

  async requestExportChallenge(
    request: Parameters<Ed25519YaoExportFlowDeps['emailOtp']['requestExportChallenge']>[0],
  ) {
    expect(request).toMatchObject({
      kind: 'near_account_challenge',
      nearAccountId: String(NEAR_ACCOUNT_ID),
      authLane: durableEd25519AuthLane(),
    });
    return { challengeId: 'challenge-email-otp-export-refresh' };
  }

  async exportSeedWithFreshAuthorization(
    args: Parameters<Ed25519YaoExportFlowDeps['emailOtp']['exportSeedWithFreshAuthorization']>[0],
  ) {
    this.exportCalls += 1;
    this.exportedCapability = args.capability;
    expect(args.walletSessionJwt).toBe('durable-wallet-session-jwt');
    expect(args.authLane).toEqual(durableEd25519AuthLane());
    return {
      artifactKind: 'near-ed25519-seed-v1' as const,
      publicKey: 'ed25519:exported-public-key',
      privateKey: 'ed25519:exported-private-key',
    };
  }

  deps(): Ed25519YaoExportFlowDeps {
    return {
      touchConfirm: {
        requestUserConfirmation: this.requestUserConfirmation.bind(this),
        exportPrivateKeysWithUi: this.unexpectedPasskeyExport.bind(this),
        initialize: this.initialize.bind(this),
      },
      resolveActiveCapability: this.resolveActiveCapability.bind(this),
      recoverPasskeyCapability: this.recoverPasskeyCapability.bind(this),
      resolvePasskeyExportContext: this.resolvePasskeyExportContext.bind(this),
      emailOtp: {
        requestExportChallenge: this.requestExportChallenge.bind(this),
        resolveExportContext: this.resolveExportContext.bind(this),
        exportSeedWithFreshAuthorization: this.exportSeedWithFreshAuthorization.bind(this),
      },
    };
  }
}

test('page-refresh Email OTP Ed25519 export resolves durable context without passkey recovery', async () => {
  const harness = new EmailOtpEd25519ExportRefreshHarness();
  const result = await exportEd25519YaoKeyWithFreshEmailOtp(harness.deps(), {
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    laneIdentity: buildLaneIdentity(),
    options: {},
    flowId: 'flow-email-otp-export-refresh',
  });

  expect(result).toEqual({
    accountId: String(NEAR_ACCOUNT_ID),
    exportedSchemes: ['ed25519'],
  });
  expect(harness.contextCalls).toBe(1);
  expect(harness.passkeyRecoveryCalls).toBe(0);
  expect(harness.exportCalls).toBe(1);
  expect(harness.exportedCapability).toEqual(CAPABILITY);
});
