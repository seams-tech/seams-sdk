import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  exportEd25519YaoKeyWithFreshAuthorization,
  type Ed25519YaoExportFlowDeps,
} from '@/core/signingEngine/flows/recovery/ed25519YaoExportFlow';
import { exactEd25519SigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
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
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

const WALLET_ID = toWalletId('email-otp-export-refresh-wallet');
const NEAR_ACCOUNT_ID = toAccountId('email-otp-export-refresh.testnet');
const NEAR_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString('email-otp-export-refresh-key');
const PROVIDER_SUBJECT_ID = 'google:email-otp-export-refresh';
const THRESHOLD_SESSION_ID = 'threshold-email-otp-export-refresh';
const WALLET_SESSION_ID = 'wallet-session-email-otp-export-refresh';
const QUOTA_ID = 'quota-email-otp-export-refresh';
const AUTHORIZATION_SESSION_ID = 'seams-session-email-otp-export-refresh';
const AUTHORIZATION_ID = 'wallet-session-authorization-email-otp-export-refresh';
const AUTHORIZATION_EXPIRES_AT_MS = 1_900_000_000_000;
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
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signerSetId: 'near-ed25519-slot-1',
    signingWorkerId: 'signing-worker-email-otp-export-refresh',
  },
  stateEpoch: 1,
} as const;

const MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'email-otp-export-refresh',
  CAPABILITY.applicationBinding.wallet_id,
);

function durableWalletSessionJwt(): string {
  const parse = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return [
    parse({ alg: 'none', typ: 'JWT' }),
    parse({
      kind: 'router_ab_ed25519_wallet_session_v1',
      walletId: String(WALLET_ID),
      authorizationId: AUTHORIZATION_ID,
      walletSessionId: WALLET_SESSION_ID,
      quotaId: QUOTA_ID,
      sid: AUTHORIZATION_SESSION_ID,
      thresholdExpiresAtMs: AUTHORIZATION_EXPIRES_AT_MS,
      exp: Math.floor(AUTHORIZATION_EXPIRES_AT_MS / 1_000),
    }),
    'durable-wallet-session-jwt',
  ].join('.');
}

async function durableAuthorization() {
  const seamsSessionId = parseSeamsSessionId(AUTHORIZATION_SESSION_ID);
  const authorizationId = parseWalletSessionAuthorizationId(AUTHORIZATION_ID);
  const walletSessionId = parseWalletSessionId(WALLET_SESSION_ID);
  const quotaId = parseMpcWalletSigningQuotaId(QUOTA_ID);
  if (!seamsSessionId.ok || !authorizationId.ok || !walletSessionId.ok || !quotaId.ok) {
    throw new Error('invalid Email OTP export authorization fixture identity');
  }
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: WALLET_ID,
    provider: 'google',
    providerUserId: PROVIDER_SUBJECT_ID,
    emailHashHex: 'email-otp-export-refresh-hash',
  });
  return buildActiveWalletSessionAuthorizationProjection({
    walletId: WALLET_ID,
    seamsSessionId: seamsSessionId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    walletSessionTokens: {
      kind: 'near_ed25519',
      ed25519: { walletSessionJwt: durableWalletSessionJwt() },
    },
    authMethod: 'email_otp',
    authority: await walletAuthAuthorityRef({ authority }),
    expiresAtMs: AUTHORIZATION_EXPIRES_AT_MS,
  });
}

function durableEd25519AuthLane() {
  const authLane = resolveEmailOtpAuthLane({
    routeAuth: { kind: 'wallet_session', jwt: durableWalletSessionJwt() },
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
    walletSessionId: WALLET_SESSION_ID,
    quotaId: QUOTA_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
}

class EmailOtpEd25519ExportRefreshHarness {
  contextCalls = 0;
  exportCalls = 0;
  exportedCapability: unknown = null;
  viewerLoadingBeforeExport = false;

  async requestUserConfirmation(request: UserConfirmRequest): Promise<UserConfirmDecision> {
    if (request.type === 'showSecurePrivateKeyUi') {
      const payload = request.payload as {
        loading?: unknown;
        keys?: Array<{ privateKey?: unknown }>;
      };
      expect(payload.loading).toBe(true);
      expect(payload.keys?.[0]?.privateKey).toBe('');
      this.viewerLoadingBeforeExport = this.exportCalls === 0;
      return { requestId: request.requestId, confirmed: true };
    }
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

  async resolvePasskeyExportContext(): Promise<never> {
    throw new Error('Email OTP export must not resolve a passkey export context');
  }

  async resolveExportContext(
    subject: Parameters<Ed25519YaoExportFlowDeps['emailOtp']['resolveExportContext']>[0],
  ) {
    this.contextCalls += 1;
    expect(subject).toEqual({
      laneIdentity: buildLaneIdentity(),
      materialActivation: MATERIAL_ACTIVATION,
    });
    return {
      kind: 'email_otp_ed25519_yao_export_context_v1' as const,
      lane: buildLaneIdentity(),
      authorization: await durableAuthorization(),
      material: { materialActivation: MATERIAL_ACTIVATION, capability: CAPABILITY },
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
    return {
      challengeId: 'challenge-email-otp-export-refresh',
      emailHint: 'a***@example.test',
      delivery: {
        kind: 'provider' as const,
        status: 'sent' as const,
        emailHint: 'a***@example.test',
      },
    };
  }

  async exportSeedWithFreshAuthorization(
    args: Parameters<Ed25519YaoExportFlowDeps['emailOtp']['exportSeedWithFreshAuthorization']>[0],
  ) {
    this.exportCalls += 1;
    expect(this.viewerLoadingBeforeExport).toBe(true);
    this.exportedCapability = args.exportContext.material.capability;
    expect(args.exportContext.authorization.walletSessionTokens.ed25519.walletSessionJwt).toContain(
      'durable-wallet-session-jwt',
    );
    return {
      artifactKind: 'near-ed25519-seed-v1' as const,
      publicKey: 'ed25519:exported-public-key',
      privateKey: 'ed25519:exported-private-key',
    };
  }

  async withThresholdEd25519CommitQueue<T>(
    args: Parameters<Ed25519YaoExportFlowDeps['withThresholdEd25519CommitQueue']>[0],
  ): Promise<T> {
    return await args.task();
  }

  deps(): Ed25519YaoExportFlowDeps {
    return {
      touchConfirm: {
        requestUserConfirmation: this.requestUserConfirmation.bind(this),
        initialize: this.initialize.bind(this),
      },
      passkeyMpcExport: {
        exportPrivateKeysWithUi: this.unexpectedPasskeyExport.bind(this),
      },
      resolvePasskeyExportContext: this.resolvePasskeyExportContext.bind(this),
      withThresholdEd25519CommitQueue: this.withThresholdEd25519CommitQueue.bind(this),
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
  const result = await exportEd25519YaoKeyWithFreshAuthorization(harness.deps(), {
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    laneIdentity: buildLaneIdentity(),
    materialActivation: MATERIAL_ACTIVATION,
    options: {},
    flowId: 'flow-email-otp-export-refresh',
  });

  expect(result).toEqual({
    accountId: String(NEAR_ACCOUNT_ID),
    exportedSchemes: ['ed25519'],
  });
  expect(harness.contextCalls).toBe(1);
  expect(harness.exportCalls).toBe(1);
  expect(harness.viewerLoadingBeforeExport).toBe(true);
  expect(harness.exportedCapability).toEqual(CAPABILITY);
});
