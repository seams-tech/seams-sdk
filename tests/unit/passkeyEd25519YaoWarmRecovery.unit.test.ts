import { expect, test } from '@playwright/test';
import { buildCurrentSealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1,
  resolvePasskeyEd25519YaoExportContextWithRuntimeV1,
  type PasskeyEd25519WarmRecoveryRuntimePorts,
} from '@/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { resolveRouterAbEd25519WalletSessionStateForOperation } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type { CurrentEd25519SealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { base64UrlEncode } from '@shared/utils/base64';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';

const NOW_MS = Date.now();
const EXPIRES_AT_MS = NOW_MS + 60_000;
const WALLET_ID = 'wallet-warm-recovery';
const NEAR_ACCOUNT_ID = 'wallet-warm-recovery.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519-key-warm-recovery';
const SIGNER_SLOT = 1;
const THRESHOLD_SESSION_ID = 'threshold-session-warm-recovery';
const SIGNING_GRANT_ID = 'signing-grant-warm-recovery';
const SIGNING_WORKER_ID = 'signing-worker-warm-recovery';
const RELAYER_URL = 'https://relay.example.test';
const RP_ID = 'wallet.example.test';
const CREDENTIAL_ID_B64U = 'credential-warm-recovery';
const PARTICIPANT_IDS = [1, 2] as const;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-warm-recovery',
  projectId: 'project-warm-recovery',
  envId: 'test',
  signingRootVersion: 'root-v1',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: SIGNING_WORKER_ID,
} as const;

function buildWalletSessionJwt(): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingGrantId: SIGNING_GRANT_ID,
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture-signature`;
}

const WALLET_SESSION_JWT = buildWalletSessionJwt();

type CapturedWarmRecoveryCall =
  | { readonly kind: 'rehydrate'; readonly input: Record<string, unknown> }
  | { readonly kind: 'claim'; readonly input: Record<string, unknown> }
  | { readonly kind: 'bootstrap'; readonly input: RequestInit }
  | { readonly kind: 'recover'; readonly input: Record<string, unknown> };

class FakeActiveClient implements RouterAbEd25519YaoActiveClientV1 {
  async createSigningShare(
    _input: RouterAbEd25519YaoClientSigningInputV1,
  ): Promise<RouterAbEd25519YaoClientSigningShareV1> {
    throw new Error('signing is outside the warm-recovery unit boundary');
  }

  metadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
    throw new Error('metadata is outside the warm-recovery unit boundary');
  }

  status(): { kind: 'active' } {
    return { kind: 'active' };
  }

  dispose(): void {}
}

function bytes(seed: number): number[] {
  return new Array<number>(32).fill(seed);
}

function buildSealedRecord(args?: {
  readonly expiresAtMs?: number;
  readonly remainingUses?: number;
}): CurrentEd25519SealedSessionRecord {
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: 'passkey',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    thresholdSessionIds: { ed25519: THRESHOLD_SESSION_ID },
    signingGrantId: SIGNING_GRANT_ID,
    walletId: WALLET_ID,
    signingRootId: 'project-warm-recovery:test',
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    relayerUrl: RELAYER_URL,
    sealedSecretB64u: 'sealed-secret-warm-recovery',
    keyVersion: 'v1',
    shamirPrimeB64u: 'shamir-prime-warm-recovery',
    issuedAtMs: NOW_MS - 1_000,
    expiresAtMs: args?.expiresAtMs ?? EXPIRES_AT_MS,
    remainingUses: args?.remainingUses ?? 3,
    updatedAtMs: NOW_MS,
    ed25519Restore: {
      sessionKind: 'jwt',
      walletSessionJwt: WALLET_SESSION_JWT,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      rpId: RP_ID,
      credentialIdB64u: CREDENTIAL_ID_B64U,
      relayerKeyId: SIGNING_WORKER_ID,
      participantIds: [...PARTICIPANT_IDS],
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signerSlot: SIGNER_SLOT,
      routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    },
  });
  if (!record || record.curve !== 'ed25519') {
    throw new Error('failed to build warm-recovery sealed record fixture');
  }
  return record;
}

function capabilityFixture(nearAccountId = NEAR_ACCOUNT_ID): Record<string, unknown> {
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    activeCapabilityBinding: bytes(9),
    registeredPublicKey: bytes(7),
    nearAccountId,
    applicationBinding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: 'project-warm-recovery:test',
      key_creation_signer_slot: SIGNER_SLOT,
    },
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    participantIds: [...PARTICIPANT_IDS],
    lifecycle: {
      lifecycleId: 'passkey-warm-recovery-lifecycle',
      rootShareEpoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
      accountId: WALLET_ID,
      walletSessionId: THRESHOLD_SESSION_ID,
      signerSetId: 'signer-set-warm-recovery',
      signingWorkerId: SIGNING_WORKER_ID,
    },
    stateEpoch: 1,
  };
}

function bootstrapFixture(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'router_ab_ed25519_yao_warm_recovery_bootstrap_v1',
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    signerSlot: SIGNER_SLOT,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
    signingWorkerId: SIGNING_WORKER_ID,
    thresholdExpiresAtMs: EXPIRES_AT_MS,
    participantIds: [...PARTICIPANT_IDS],
    authority: buildPasskeyWalletAuthAuthority({
      walletId: WALLET_ID,
      rpId: RP_ID,
      credentialIdB64u: CREDENTIAL_ID_B64U,
    }),
    authorityScope: { kind: 'passkey_rp', rpId: RP_ID },
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    capability: capabilityFixture(),
    ...overrides,
  };
}

function recoveryWalletSessionState() {
  const record = persistWarmSessionEd25519Capability({
    kind: 'jwt_passkey',
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    rpId: RP_ID,
    relayerUrl: RELAYER_URL,
    relayerKeyId: SIGNING_WORKER_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    participantIds: PARTICIPANT_IDS,
    signerSlot: SIGNER_SLOT,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    sessionId: THRESHOLD_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
    expiresAtMs: EXPIRES_AT_MS,
    remainingUses: 3,
    jwt: WALLET_SESSION_JWT,
    passkeyCredentialIdB64u: CREDENTIAL_ID_B64U,
    source: 'login',
  });
  const state = resolveRouterAbEd25519WalletSessionStateForOperation({ record, nowMs: NOW_MS });
  if (!state) throw new Error('failed to build recovered wallet session fixture');
  return state;
}

class WarmRecoveryFixture {
  readonly calls: CapturedWarmRecoveryCall[] = [];
  readonly activeClient = new FakeActiveClient();
  sealedRecords: CurrentEd25519SealedSessionRecord[] = [buildSealedRecord()];
  rehydrateResult: WarmSessionStatusResult = {
    ok: true,
    remainingUses: 3,
    expiresAtMs: EXPIRES_AT_MS,
  };
  claimResult: WarmSessionClaimResult = {
    ok: true,
    prfFirstB64u: base64UrlEncode(new Uint8Array(32).fill(5)),
    remainingUses: 3,
    expiresAtMs: EXPIRES_AT_MS,
  };
  bootstrapResponse = new Response(JSON.stringify(bootstrapFixture()), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });

  readonly workerPorts = {
    rehydrateWarmSessionMaterial: this.rehydrateWarmSessionMaterial.bind(this),
    claimWarmSessionMaterial: this.claimWarmSessionMaterial.bind(this),
  };

  readonly runtime: PasskeyEd25519WarmRecoveryRuntimePorts = {
    listExactSealedSessionsForWallet: this.listExactSealedSessionsForWallet.bind(this),
    recoverCapability: this.recoverCapability.bind(this),
    nowMs: this.nowMs.bind(this),
  };

  async rehydrateWarmSessionMaterial(
    input: Parameters<typeof this.workerPorts.rehydrateWarmSessionMaterial>[0],
  ): Promise<WarmSessionStatusResult> {
    this.calls.push({ kind: 'rehydrate', input });
    return this.rehydrateResult;
  }

  async claimWarmSessionMaterial(
    input: Parameters<typeof this.workerPorts.claimWarmSessionMaterial>[0],
  ): Promise<WarmSessionClaimResult> {
    this.calls.push({ kind: 'claim', input });
    return this.claimResult;
  }

  async listExactSealedSessionsForWallet(): Promise<CurrentEd25519SealedSessionRecord[]> {
    return this.sealedRecords;
  }

  async recoverCapability(
    input: Parameters<PasskeyEd25519WarmRecoveryRuntimePorts['recoverCapability']>[0],
  ): ReturnType<PasskeyEd25519WarmRecoveryRuntimePorts['recoverCapability']> {
    this.calls.push({ kind: 'recover', input });
    return {
      activeClient: this.activeClient,
      walletSessionState: recoveryWalletSessionState(),
      parsed: input.parsed,
    };
  }

  nowMs(): number {
    return NOW_MS;
  }

  async fetch(_input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    this.calls.push({ kind: 'bootstrap', input: init ?? {} });
    return this.bootstrapResponse.clone();
  }
}

function warmRecoveryInput(fixture: WarmRecoveryFixture) {
  return {
    subject: {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      signerSlot: SIGNER_SLOT,
      thresholdSessionId: THRESHOLD_SESSION_ID,
    },
    relayerUrl: RELAYER_URL,
    rpId: RP_ID,
    fetch: fixture.fetch.bind(fixture),
    ports: fixture.workerPorts,
  };
}

function callKinds(call: CapturedWarmRecoveryCall): CapturedWarmRecoveryCall['kind'] {
  return call.kind;
}

test('restores and claims sealed PRF without a credential prompt before warm Yao recovery', async () => {
  const fixture = new WarmRecoveryFixture();
  const result = await recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1(
    warmRecoveryInput(fixture),
    fixture.runtime,
  );

  expect(result.kind).toBe('recovered');
  expect(fixture.calls.map(callKinds)).toEqual(['bootstrap', 'rehydrate', 'claim', 'recover']);
  expect(fixture.calls[2]).toMatchObject({
    kind: 'claim',
    input: {
      sessionId: THRESHOLD_SESSION_ID,
      uses: 1,
      consume: false,
      curve: 'ed25519',
      chain: 'near',
    },
  });
  expect(fixture.calls[0]).toMatchObject({
    kind: 'bootstrap',
    input: {
      headers: {
        Authorization: `Bearer ${WALLET_SESSION_JWT}`,
      },
    },
  });
});

test('resolves passkey export context without restoring PRF or activating a signing client', async () => {
  const fixture = new WarmRecoveryFixture();
  const result = await resolvePasskeyEd25519YaoExportContextWithRuntimeV1(
    {
      subject: warmRecoveryInput(fixture).subject,
      relayerUrl: RELAYER_URL,
      fetch: fixture.fetch.bind(fixture),
    },
    fixture.runtime,
  );

  expect(result.kind).toBe('ready');
  if (result.kind !== 'ready') throw new Error('expected durable passkey export context');
  expect(result.context).toMatchObject({
    kind: 'passkey_ed25519_yao_export_context_v1',
    relayerUrl: RELAYER_URL,
    rpId: RP_ID,
    descriptor: {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      signerSlot: SIGNER_SLOT,
      credentialIdB64u: CREDENTIAL_ID_B64U,
      session: {
        thresholdSessionId: THRESHOLD_SESSION_ID,
        signingGrantId: SIGNING_GRANT_ID,
        walletSessionJwt: WALLET_SESSION_JWT,
      },
    },
  });
  expect(fixture.calls.map(callKinds)).toEqual(['bootstrap']);
});

test('returns unavailable only for explicit sealed-session and expired JWT states', async () => {
  const missing = new WarmRecoveryFixture();
  missing.sealedRecords = [];
  await expect(
    recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1(
      warmRecoveryInput(missing),
      missing.runtime,
    ),
  ).resolves.toEqual({ kind: 'unavailable', reason: 'sealed_session_missing' });

  const expired = new WarmRecoveryFixture();
  expired.sealedRecords = [buildSealedRecord({ expiresAtMs: NOW_MS })];
  await expect(
    recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1(
      warmRecoveryInput(expired),
      expired.runtime,
    ),
  ).resolves.toEqual({ kind: 'unavailable', reason: 'sealed_session_expired' });

  const exhausted = new WarmRecoveryFixture();
  exhausted.sealedRecords = [buildSealedRecord({ remainingUses: 0 })];
  await expect(
    recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1(
      warmRecoveryInput(exhausted),
      exhausted.runtime,
    ),
  ).resolves.toEqual({ kind: 'unavailable', reason: 'sealed_session_exhausted' });

  const jwtExpired = new WarmRecoveryFixture();
  jwtExpired.bootstrapResponse = new Response(
    JSON.stringify({ ok: false, code: 'wallet_session_expired', message: 'expired' }),
    { status: 401, headers: { 'content-type': 'application/json' } },
  );
  await expect(
    recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1(
      warmRecoveryInput(jwtExpired),
      jwtExpired.runtime,
    ),
  ).resolves.toEqual({ kind: 'unavailable', reason: 'wallet_session_expired' });

  const invalidJwt = new WarmRecoveryFixture();
  invalidJwt.bootstrapResponse = new Response(
    JSON.stringify({ ok: false, code: 'recovery_wallet_session_invalid', message: 'invalid' }),
    { status: 401, headers: { 'content-type': 'application/json' } },
  );
  await expect(
    recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1(
      warmRecoveryInput(invalidJwt),
      invalidJwt.runtime,
    ),
  ).rejects.toThrow('recovery_wallet_session_invalid');
});

test('treats warm bootstrap identity substitution as a fatal continuity failure', async () => {
  const fixture = new WarmRecoveryFixture();
  fixture.bootstrapResponse = new Response(
    JSON.stringify(bootstrapFixture({ nearAccountId: 'substituted.testnet' })),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );

  await expect(
    recoverPasskeyEd25519YaoFromSealedSessionWithRuntimeV1(
      warmRecoveryInput(fixture),
      fixture.runtime,
    ),
  ).rejects.toThrow('does not match the exact sealed Ed25519 lane');
  expect(fixture.calls.map(callKinds)).toEqual(['bootstrap']);
});
