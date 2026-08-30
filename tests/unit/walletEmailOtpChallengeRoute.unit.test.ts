import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { deriveRouterAbEd25519YaoRuntimePolicyBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import { handleWalletEmailOtpChallenge } from '../../packages/wallet-server/src/router/transport/fetch/routes/sessions';
import { parseWalletAuthMethodId } from '../../packages/shared-ts/src/utils/domainIds';
import { buildEmailOtpWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '../../packages/shared-ts/src/utils/routerAbNormalSigningIdentity';
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';

const WALLET_ID = 'alice.testnet';
const OTHER_WALLET_ID = 'bob.testnet';
const ORG_ID = 'org-a';
const PROVIDER_USER_ID = 'google:alice';
const EMAIL = 'alice@example.test';
const EMAIL_HASH_HEX = 'a'.repeat(64);
const WALLET_AUTH_METHOD_ID = 'email-otp-method-a';
const ECDSA_KEY_HANDLE = 'ecdsa-key-handle-a';
const ECDSA_RUNTIME_POLICY_SCOPE = {
  orgId: ORG_ID,
  projectId: 'project-a',
  envId: 'env-a',
  signingRootVersion: 'v1',
} as const;
const ED25519_RUNTIME_POLICY_SCOPE = {
  orgId: ORG_ID,
  projectId: 'project-a',
  envId: 'env-a',
  signingRootVersion: 'v1',
} as const;
const ED25519_SIGNING_WORKER_ID = 'email-otp-signing-worker-a';
const ED25519_THRESHOLD_SESSION_ID = 'email-otp-threshold-session-a';
const ED25519_PARTICIPANT_IDS: readonly [number, number] = [1, 2];
const ED25519_REGISTERED_PUBLIC_KEY = new Array<number>(32).fill(34);

type RouteState = {
  readonly exactCalls: unknown[];
  readonly challengeCalls: unknown[];
  readonly ed25519MaterialCalls: unknown[];
  readonly ecdsaMaterialCalls: unknown[];
  readonly exactResolution: unknown;
  readonly ed25519MaterialResolution: unknown;
  readonly ecdsaMaterialResolution: unknown;
};

function selectedAuthority() {
  const parsedMethodId = parseWalletAuthMethodId(WALLET_AUTH_METHOD_ID);
  if (!parsedMethodId.ok) throw new Error(parsedMethodId.error.message);
  return {
    ...buildEmailOtpWalletAuthAuthority({
      walletId: WALLET_ID,
      provider: 'google',
      providerUserId: PROVIDER_USER_ID,
      emailHashHex: EMAIL_HASH_HEX,
    }),
    bindingId: parsedMethodId.value,
  };
}

function challengeResult() {
  return {
    ok: true,
    challenge: {
      challengeId: 'challenge-a',
      issuedAtMs: 1_000,
      expiresAtMs: 61_000,
      userId: PROVIDER_USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      otpChannel: 'email_otp',
      ownerProofBindingDigest: 'binding-a',
      action: 'wallet_email_otp_login',
      operation: 'wallet_unlock',
    },
    delivery: {
      kind: 'development',
      status: 'sent',
      mode: 'memory',
      emailHint: 'a***e@e***e.test',
    },
  };
}

async function activeAuthority(keyFamily: 'ed25519' | 'ecdsa_secp256k1') {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: `email-otp-${keyFamily}`,
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    keyFamily,
    identity: {
      walletId: WALLET_ID,
      authorityId: `authority:email-otp-${keyFamily}`,
      walletAuthMethodId: WALLET_AUTH_METHOD_ID,
      rpId: 'email-otp.example.test',
    },
  });
  return fixture.authority;
}

async function ed25519MaterialResolution(materialActivation: RouterAbMpcMaterialActivationRefWire) {
  return {
    ok: true as const,
    materialActivation,
    nearAccountId: WALLET_ID,
    signerSlot: 1,
    signingWorkerId: ED25519_SIGNING_WORKER_ID,
    participantIds: ED25519_PARTICIPANT_IDS,
    runtimePolicyScope: ED25519_RUNTIME_POLICY_SCOPE,
    exportIdentity: {
      scope: {
        lifecycle_id: 'email-otp-lifecycle-a',
        root_share_epoch: ED25519_RUNTIME_POLICY_SCOPE.signingRootVersion,
        account_id: WALLET_ID,
        threshold_session_id: ED25519_THRESHOLD_SESSION_ID,
        signer_set_id: 'email-otp-signer-set-a',
        signing_worker_id: ED25519_SIGNING_WORKER_ID,
        material_activation: materialActivation,
      },
      application_binding: {
        wallet_id: WALLET_ID,
        near_ed25519_signing_key_id: 'email-otp-near-key-a',
        signing_root_id: 'project-a:env-a',
        key_creation_signer_slot: 1,
      },
      participant_ids: ED25519_PARTICIPANT_IDS,
      registered_public_key: ED25519_REGISTERED_PUBLIC_KEY,
      state_epoch: 1,
      runtime_policy_binding: await deriveRouterAbEd25519YaoRuntimePolicyBindingV1(
        ED25519_RUNTIME_POLICY_SCOPE,
      ),
    },
  };
}

function context(body: unknown, state: RouteState) {
  return {
    method: 'POST',
    pathname: '/wallet/email-otp/challenge',
    request: new Request('https://relay.localhost/wallet/email-otp/challenge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://app.example.localhost',
      },
      body: JSON.stringify(body),
    }),
    service: {
      authorizedOperations: { tenantId: ORG_ID },
      emailOtp: {
        readActiveEmailOtpEnrollment: async () => ({
          ok: true,
          enrollment: {
            providerUserId: PROVIDER_USER_ID,
            verifiedEmail: EMAIL,
          },
        }),
        createEmailOtpChallenge: async (input: unknown) => {
          state.challengeCalls.push(input);
          return challengeResult();
        },
      },
      walletUnlock: {
        resolveEmailOtpAuthorityForUnlock: async (input: unknown) => {
          state.exactCalls.push(input);
          return state.exactResolution;
        },
      },
      walletRegistration: {
        resolveEd25519MaterialActivation: async (input: unknown) => {
          state.ed25519MaterialCalls.push(input);
          return state.ed25519MaterialResolution;
        },
        resolveEcdsaMaterialActivation: async (input: unknown) => {
          state.ecdsaMaterialCalls.push(input);
          return state.ecdsaMaterialResolution;
        },
      },
    },
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

function state(overrides: Partial<RouteState> = {}): RouteState {
  return {
    exactCalls: [],
    challengeCalls: [],
    ed25519MaterialCalls: [],
    ecdsaMaterialCalls: [],
    exactResolution: { kind: 'rejected', code: 'unused', message: 'unused' },
    ed25519MaterialResolution: { ok: false, code: 'unused', message: 'unused' },
    ecdsaMaterialResolution: { ok: false, code: 'unused', message: 'unused' },
    ...overrides,
  };
}

test('an exact Email OTP method returns ed25519_only for an Ed25519 active authority', async () => {
  const authority = await activeAuthority('ed25519');
  const materialActivation = authority.signerActivations.ed25519?.materialActivation;
  if (!materialActivation) throw new Error('Ed25519 authority fixture has no material activation');
  const materialActivationWire = routerAbMpcMaterialActivationRefToWire(materialActivation);
  const routeState = state({
    exactResolution: {
      kind: 'active_authority',
      authority,
      walletAuthAuthority: selectedAuthority(),
    },
    ed25519MaterialResolution: await ed25519MaterialResolution(materialActivationWire),
  });
  const response = await handleWalletEmailOtpChallenge(
    context(
      {
        walletId: WALLET_ID,
        walletAuthMethodId: WALLET_AUTH_METHOD_ID,
        otpChannel: 'email_otp',
        operation: 'wallet_unlock',
      },
      routeState,
    ),
  );

  expect(response?.status).toBe(200);
  expect(routeState.exactCalls).toEqual([
    {
      walletId: WALLET_ID,
      orgId: ORG_ID,
      walletAuthMethodId: WALLET_AUTH_METHOD_ID,
      providerUserId: PROVIDER_USER_ID,
    },
  ]);
  expect(routeState.challengeCalls).toHaveLength(1);
  expect(routeState.ed25519MaterialCalls).toEqual([
    {
      walletId: WALLET_ID,
      materialActivation: materialActivationWire,
    },
  ]);
  await expect(response?.json()).resolves.toMatchObject({
    ok: true,
    walletAuthMethodId: WALLET_AUTH_METHOD_ID,
    signerSelection: {
      kind: 'ed25519_only',
      materialActivation,
      nearAccountId: WALLET_ID,
      signerSlot: 1,
      operationalPublicKey: `ed25519:${base58Encode(
        Uint8Array.from(ED25519_REGISTERED_PUBLIC_KEY),
      )}`,
      thresholdSessionId: ED25519_THRESHOLD_SESSION_ID,
      runtimePolicyScope: ED25519_RUNTIME_POLICY_SCOPE,
    },
  });
});

test('an exact Email OTP method returns ECDSA signer selection from the active authority', async () => {
  const authority = await activeAuthority('ecdsa_secp256k1');
  const materialActivation = authority.signerActivations.ecdsa?.materialActivation;
  if (!materialActivation) throw new Error('ECDSA authority fixture has no material activation');
  const routeState = state({
    exactResolution: {
      kind: 'active_authority',
      authority,
      walletAuthAuthority: selectedAuthority(),
    },
    ecdsaMaterialResolution: {
      ok: true,
      keyHandle: ECDSA_KEY_HANDLE,
      runtimePolicyScope: ECDSA_RUNTIME_POLICY_SCOPE,
      materialActivation: routerAbMpcMaterialActivationRefToWire(materialActivation),
    },
  });
  const response = await handleWalletEmailOtpChallenge(
    context(
      {
        walletId: WALLET_ID,
        walletAuthMethodId: WALLET_AUTH_METHOD_ID,
        otpChannel: 'email_otp',
        operation: 'wallet_unlock',
      },
      routeState,
    ),
  );

  expect(response?.status).toBe(200);
  expect(routeState.ecdsaMaterialCalls).toHaveLength(1);
  await expect(response?.json()).resolves.toMatchObject({
    ok: true,
    walletAuthMethodId: WALLET_AUTH_METHOD_ID,
    signerSelection: {
      kind: 'ecdsa',
      keyHandle: ECDSA_KEY_HANDLE,
      runtimePolicyScope: ECDSA_RUNTIME_POLICY_SCOPE,
    },
  });
});

test('wrong-wallet, wrong-kind, and revoked exact methods are rejected before challenge creation', async () => {
  const rejectionCases = [
    {
      name: 'wrong wallet',
      walletId: OTHER_WALLET_ID,
      message: 'Selected Email OTP method belongs to another wallet',
    },
    {
      name: 'wrong kind',
      walletId: WALLET_ID,
      message: 'Selected wallet auth method is not Email OTP',
    },
    {
      name: 'revoked method',
      walletId: WALLET_ID,
      message: 'Selected Email OTP method is revoked',
    },
  ] as const;

  for (const rejectionCase of rejectionCases) {
    const routeState = state({
      exactResolution: {
        kind: 'rejected',
        code: 'unauthorized',
        message: rejectionCase.message,
      },
    });
    const response = await handleWalletEmailOtpChallenge(
      context(
        {
          walletId: rejectionCase.walletId,
          walletAuthMethodId: WALLET_AUTH_METHOD_ID,
          otpChannel: 'email_otp',
          operation: 'wallet_unlock',
        },
        routeState,
      ),
    );

    expect(response?.status, rejectionCase.name).toBe(403);
    await expect(response?.json(), rejectionCase.name).resolves.toMatchObject({
      ok: false,
      code: 'unauthorized',
      message: rejectionCase.message,
    });
    expect(routeState.challengeCalls, rejectionCase.name).toEqual([]);
    expect(routeState.exactCalls, rejectionCase.name).toHaveLength(1);
  }
});

test('Email OTP challenge rejects an omitted exact wallet auth method', async () => {
  const routeState = state();
  const response = await handleWalletEmailOtpChallenge(
    context(
      {
        walletId: WALLET_ID,
        otpChannel: 'email_otp',
        operation: 'wallet_unlock',
      },
      routeState,
    ),
  );

  expect(response?.status).toBe(400);
  await expect(response?.json()).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
    message: expect.stringContaining('walletAuthMethodId'),
  });
  expect(routeState.exactCalls).toEqual([]);
  expect(routeState.challengeCalls).toEqual([]);
});
