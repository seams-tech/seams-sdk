import { expect, test } from '@playwright/test';
import { base58Encode } from '@shared/utils/base58';
import {
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  parsePasskeyEd25519YaoSyncResponseV1,
  recoverPasskeyEd25519YaoCapabilityV1,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import {
  RouterAbEd25519YaoHttpActivationTransportV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';

const WALLET_ID = 'wallet-recovery-1';
const NEAR_ACCOUNT_ID = 'wallet-recovery.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519ks_wallet_recovery_1';
const WALLET_SESSION_ID = 'wallet-session-recovery-1';
const SIGNING_WORKER_ID = 'signing-worker-recovery-1';
const ROOT_SHARE_EPOCH = 'root-share-epoch-recovery-1';
const PARTICIPANT_IDS = [11, 29] as const;
const WALLET_SESSION_JWT = 'wallet-session-jwt-secret';

type SyncResponseFixtureInput = {
  readonly responseWalletId: string;
  readonly sessionWalletId: string;
  readonly capabilityWalletId: string;
  readonly capabilityAccountId: string;
  readonly capabilityNearAccountId: string;
  readonly sessionId: string;
  readonly capabilitySessionId: string;
  readonly sessionParticipantIds: readonly [number, number];
  readonly capabilityParticipantIds: readonly [number, number];
  readonly relayerKeyId: string;
  readonly sessionSigningWorkerId: string;
  readonly capabilitySigningWorkerId: string;
  readonly sessionRootShareEpoch: string;
  readonly capabilityRootShareEpoch: string;
  readonly capabilityRuntimeRootShareEpoch: string;
  readonly applicationSigningRootId: string;
  readonly responsePublicKeySeed: number;
  readonly capabilityPublicKeySeed: number;
  readonly capabilityStateEpoch: number;
  readonly recoveryKind: string;
  readonly activeCapabilityBindingLength: number;
};

type CapturedFetch = {
  url: string;
  init: RequestInit;
};

let capturedFetch: CapturedFetch | null = null;
let nextFetchResponse = new Response('{}', {
  status: 200,
  headers: { 'content-type': 'application/json' },
});

async function recoveryTransportFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  capturedFetch = {
    url: input instanceof Request ? input.url : String(input),
    init: init ?? {},
  };
  return nextFetchResponse.clone();
}

async function unexpectedFetch(): Promise<Response> {
  throw new Error('fetch must not run for a malformed sync response');
}

function bytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function defaultSyncResponseFixtureInput(): SyncResponseFixtureInput {
  return {
    responseWalletId: WALLET_ID,
    sessionWalletId: WALLET_ID,
    capabilityWalletId: WALLET_ID,
    capabilityAccountId: WALLET_ID,
    capabilityNearAccountId: NEAR_ACCOUNT_ID,
    sessionId: WALLET_SESSION_ID,
    capabilitySessionId: WALLET_SESSION_ID,
    sessionParticipantIds: PARTICIPANT_IDS,
    capabilityParticipantIds: PARTICIPANT_IDS,
    relayerKeyId: SIGNING_WORKER_ID,
    sessionSigningWorkerId: SIGNING_WORKER_ID,
    capabilitySigningWorkerId: SIGNING_WORKER_ID,
    sessionRootShareEpoch: ROOT_SHARE_EPOCH,
    capabilityRootShareEpoch: ROOT_SHARE_EPOCH,
    capabilityRuntimeRootShareEpoch: ROOT_SHARE_EPOCH,
    applicationSigningRootId: 'project-recovery:test',
    responsePublicKeySeed: 12,
    capabilityPublicKeySeed: 12,
    capabilityStateEpoch: 1,
    recoveryKind: 'router_ab_ed25519_yao_sync_recovery_v1',
    activeCapabilityBindingLength: 32,
  };
}

function syncResponseFixture(
  overrides: Partial<SyncResponseFixtureInput> = {},
): Record<string, unknown> {
  const input = { ...defaultSyncResponseFixtureInput(), ...overrides };
  const responsePublicKey = bytes(input.responsePublicKeySeed);
  return {
    ok: true,
    verified: true,
    walletId: input.responseWalletId,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    signerSlot: 3,
    publicKey: `ed25519:${base58Encode(Uint8Array.from(responsePublicKey))}`,
    credentialIdB64u: 'recovery-credential-id',
    credentialPublicKeyB64u: 'recovery-credential-public-key',
    thresholdEd25519: {
      relayerKeyId: input.relayerKeyId,
      participantIds: [...input.sessionParticipantIds],
      session: {
        sessionKind: 'jwt',
        walletSessionJwt: WALLET_SESSION_JWT,
        walletId: input.sessionWalletId,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        thresholdSessionId: input.sessionId,
        signingGrantId: 'signing-grant-recovery-1',
        expiresAtMs: Date.now() + 60_000,
        participantIds: [...input.sessionParticipantIds],
        remainingUses: 4,
        signingRootId: 'project-recovery:test',
        signingRootVersion: input.sessionRootShareEpoch,
        runtimePolicyScope: {
          orgId: 'org-recovery',
          projectId: 'project-recovery',
          envId: 'test',
          signingRootVersion: input.sessionRootShareEpoch,
        },
        routerAbNormalSigning: {
          kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
          signingWorkerId: input.sessionSigningWorkerId,
        },
      },
    },
    ed25519YaoRecovery: {
      kind: input.recoveryKind,
      capability: {
        kind: 'router_ab_ed25519_yao_active_capability_v1',
        activeCapabilityBinding: bytes(20, input.activeCapabilityBindingLength),
        registeredPublicKey: bytes(input.capabilityPublicKeySeed),
        nearAccountId: input.capabilityNearAccountId,
        applicationBinding: {
          wallet_id: input.capabilityWalletId,
          near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
          signing_root_id: input.applicationSigningRootId,
          key_creation_signer_slot: 3,
        },
        runtimePolicyScope: {
          orgId: 'org-recovery',
          projectId: 'project-recovery',
          envId: 'test',
          signingRootVersion: input.capabilityRuntimeRootShareEpoch,
        },
        participantIds: [...input.capabilityParticipantIds],
        lifecycle: {
          lifecycleId: 'passkey-recovery-capability-lifecycle',
          rootShareEpoch: input.capabilityRootShareEpoch,
          accountId: input.capabilityAccountId,
          walletSessionId: input.capabilitySessionId,
          signerSetId: 'signer-set-recovery-1',
          signingWorkerId: input.capabilitySigningWorkerId,
        },
        stateEpoch: input.capabilityStateEpoch,
      },
    },
  };
}

function requireAdmissionRequest(): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
    scope: {
      lifecycle_id: 'recovery-lifecycle-transport-1',
      root_share_epoch: ROOT_SHARE_EPOCH,
      account_id: WALLET_ID,
      wallet_session_id: WALLET_SESSION_ID,
      signer_set_id: 'signer-set-recovery-1',
      signing_worker_id: SIGNING_WORKER_ID,
    },
    application_binding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: 'project-recovery:test',
      key_creation_signer_slot: 3,
    },
    participant_ids: PARTICIPANT_IDS,
    active_capability_binding: bytes(20),
    replacement_capability_binding: bytes(21),
    registered_public_key: bytes(12),
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function resetTransportFetch(response: Response): void {
  capturedFetch = null;
  nextFetchResponse = response;
}

test.describe('passkey Ed25519 Yao browser recovery boundary', () => {
  test('parses one exact verified sync response', () => {
    const parsed = parsePasskeyEd25519YaoSyncResponseV1(syncResponseFixture());

    expect(parsed).toMatchObject({
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      signerSlot: 3,
      relayerKeyId: SIGNING_WORKER_ID,
      session: {
        walletSessionJwt: WALLET_SESSION_JWT,
        thresholdSessionId: WALLET_SESSION_ID,
        signingGrantId: 'signing-grant-recovery-1',
        remainingUses: 4,
      },
      capability: {
        participantIds: PARTICIPANT_IDS,
        stateEpoch: 1,
        lifecycle: {
          rootShareEpoch: ROOT_SHARE_EPOCH,
          accountId: WALLET_ID,
          walletSessionId: WALLET_SESSION_ID,
          signingWorkerId: SIGNING_WORKER_ID,
        },
      },
    });
  });

  test('rejects malformed and unverified sync responses at the parser boundary', () => {
    const malformed: readonly unknown[] = [
      null,
      { ok: true, verified: false },
      syncResponseFixture({ recoveryKind: 'substituted_recovery_kind' }),
      syncResponseFixture({ activeCapabilityBindingLength: 31 }),
      syncResponseFixture({ capabilityStateEpoch: 0 }),
    ];

    for (const response of malformed) {
      expect(() => parsePasskeyEd25519YaoSyncResponseV1(response)).toThrow();
    }
  });

  test('rejects wallet, session, participant, worker, root, and public-key substitutions', () => {
    const substitutions: ReadonlyArray<{
      label: string;
      response: Record<string, unknown>;
    }> = [
      {
        label: 'wallet',
        response: syncResponseFixture({ capabilityWalletId: 'substituted-wallet' }),
      },
      {
        label: 'session',
        response: syncResponseFixture({ capabilitySessionId: 'substituted-session' }),
      },
      {
        label: 'NEAR account',
        response: syncResponseFixture({ capabilityNearAccountId: 'substituted.testnet' }),
      },
      {
        label: 'participants',
        response: syncResponseFixture({ capabilityParticipantIds: [11, 31] }),
      },
      {
        label: 'SigningWorker',
        response: syncResponseFixture({ capabilitySigningWorkerId: 'substituted-worker' }),
      },
      {
        label: 'root epoch',
        response: syncResponseFixture({ capabilityRootShareEpoch: 'substituted-root' }),
      },
      {
        label: 'runtime policy root',
        response: syncResponseFixture({
          capabilityRuntimeRootShareEpoch: 'substituted-runtime-root',
        }),
      },
      {
        label: 'public key',
        response: syncResponseFixture({ responsePublicKeySeed: 99 }),
      },
    ];

    for (const substitution of substitutions) {
      expect(
        () => parsePasskeyEd25519YaoSyncResponseV1(substitution.response),
        substitution.label,
      ).toThrow('Yao recovery response does not preserve');
    }
  });

  test('zeroizes the owned PRF when sync parsing fails before WASM initialization', async () => {
    const ownedPasskeyPrfFirst = new Uint8Array(32).fill(77);

    await expect(
      recoverPasskeyEd25519YaoCapabilityV1({
        syncResponse: null,
        ownedPasskeyPrfFirst,
        relayerUrl: 'https://router.example.test',
        rpId: 'wallet.example.test',
        fetch: unexpectedFetch,
      }),
    ).rejects.toThrow('sync-account response must be an object');
    expect(ownedPasskeyPrfFirst).toEqual(new Uint8Array(32));
  });

  test('keeps Wallet Session authorization in the transport header', async () => {
    resetTransportFetch(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
      routerOrigin: 'https://router.example.test',
      authorization: `Bearer ${WALLET_SESSION_JWT}`,
      fetch: recoveryTransportFetch,
    });

    await expect(
      transport.send({
        kind: 'recovery_admit',
        path: ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
        body: requireAdmissionRequest(),
      }),
    ).resolves.toEqual({ ok: true, value: { ok: true } });
    expect(capturedFetch?.url).toBe(
      'https://router.example.test/router-ab/ed25519/yao/recovery/admit',
    );
    expect(new Headers(capturedFetch?.init.headers).get('authorization')).toBe(
      `Bearer ${WALLET_SESSION_JWT}`,
    );
    expect(String(capturedFetch?.init.body)).not.toContain(WALLET_SESSION_JWT);
  });

  test('returns a typed transport failure for malformed router JSON', async () => {
    resetTransportFetch(
      new Response('not-json', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
      routerOrigin: 'https://router.example.test',
      authorization: `Bearer ${WALLET_SESSION_JWT}`,
      fetch: recoveryTransportFetch,
    });

    await expect(
      transport.send({
        kind: 'recovery_admit',
        path: ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
        body: requireAdmissionRequest(),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_router_response',
      status: 200,
    });
  });
});
