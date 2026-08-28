import { expect, test } from '@playwright/test';
import { alphabetizeStringify, sha256BytesUtf8 } from '../../packages/shared-ts/src/utils/digests';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import {
  buildPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  runRouterAbEd25519YaoRegistrationSideEffectV2,
  runRouterAbEd25519YaoRegistrationSideEffectV1,
  throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1,
  type RouterAbEd25519YaoRegistrationSideEffectClaimV1,
  type RouterAbEd25519YaoRegistrationSideEffectCompletionV1,
  type RouterAbEd25519YaoRegistrationSideEffectRecordV2,
  type RouterAbEd25519YaoRegistrationSideEffectStoreV2,
  type RouterAbEd25519YaoRegistrationSideEffectWritableRecordV2,
  parseRouterAbEd25519YaoRegistrationSideEffectRecordV2WithLegacy,
} from '../../packages/wallet-server/src/router/domains/ed25519Yao/registration/routerAbEd25519YaoRegistrationSideEffectBoundary';
import type {
  VersionedJsonRecordPutResult,
  VersionedJsonRecordReadResult,
} from '../../packages/wallet-server/src/router/framework/versionedJsonRecordStore';
import {
  parseWalletRegistrationSessionCommitReceiptV2,
  projectWalletRegistrationSessionCommitReceiptV2,
} from '../../packages/wallet-server/src/router/cloudflare/d1/registration/walletRegistrationSessionCommitReceipt';
import { createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1 } from '../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationRequestScopedRuntime';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import {
  AlwaysConflictRegistrationBridgePartitionStore,
  createRegistrationBridgePartitionStore,
  OneConflictRegistrationBridgePartitionStore,
  RegistrationSideEffectMemoryStore,
  UnavailableRouterAbEd25519YaoRegistrationBackend,
} from './helpers/routerAbEd25519YaoRegistrationBridge.fixtures';

const REQUEST_FINGERPRINT = 'I1f3l6f4R6TT7IqKCMGEjU0RiRkmphAMYj6QJfG5UvQ';

type TestResponse = {
  readonly ok: true;
  readonly receipt: string;
};

type PreparedMarker = { readonly kind: 'prepared_test_effect' };

type CredentialFreeReceipt = {
  readonly kind: 'credential_free_test_receipt';
  readonly committedIdentity: string;
};

type CredentialBearingResponse = {
  readonly ok: true;
  readonly committedIdentity: string;
  readonly walletSessionToken: string;
};

type CredentialFreeStoreRecord = {
  readonly version: number;
  readonly value: RouterAbEd25519YaoRegistrationSideEffectRecordV2<
    CredentialFreeReceipt,
    PreparedMarker,
    CredentialBearingResponse
  >;
};

class CredentialFreeRegistrationStore implements RouterAbEd25519YaoRegistrationSideEffectStoreV2<
  CredentialFreeReceipt,
  PreparedMarker,
  CredentialBearingResponse
> {
  readonly records = new Map<string, CredentialFreeStoreRecord>();

  async read(
    key: string,
  ): Promise<
    VersionedJsonRecordReadResult<
      RouterAbEd25519YaoRegistrationSideEffectRecordV2<CredentialFreeReceipt, PreparedMarker>
    >
  > {
    const record = this.records.get(key);
    return record
      ? {
          kind: 'present',
          version: String(record.version),
          value: structuredClone(record.value),
        }
      : { kind: 'missing' };
  }

  async put(
    key: string,
    value: RouterAbEd25519YaoRegistrationSideEffectWritableRecordV2<
      CredentialFreeReceipt,
      PreparedMarker
    >,
    expectedVersion: string | null,
  ): Promise<VersionedJsonRecordPutResult> {
    const current = this.records.get(key);
    if (
      (expectedVersion === null && current) ||
      (expectedVersion !== null && String(current?.version) !== expectedVersion)
    ) {
      return { kind: 'version_mismatch' };
    }
    const version = (current?.version ?? 0) + 1;
    this.records.set(key, { version, value: structuredClone(value) });
    return { kind: 'stored', version: String(version) };
  }
}

function projectCredentialFreeTestReceipt(
  response: CredentialBearingResponse,
): CredentialFreeReceipt {
  return {
    kind: 'credential_free_test_receipt',
    committedIdentity: response.committedIdentity,
  };
}

function replayCredentialFreeTestReceipt(
  receipt: CredentialFreeReceipt,
): CredentialBearingResponse {
  return {
    ok: true,
    committedIdentity: receipt.committedIdentity,
    walletSessionToken: 'replayed-ephemeral-token',
  };
}

async function deriveTestPreparedArtifactFingerprint(prepared: unknown): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(prepared)));
}

async function prepareTestEffect(): Promise<PreparedMarker> {
  return { kind: 'prepared_test_effect' };
}

async function executeRetryableTestEffect(): Promise<TestResponse> {
  return throwIfRouterAbEd25519YaoRetryableSideEffectFailureV1({
    ok: false,
    code: 'not_configured',
    message: 'runtime is temporarily unavailable',
  });
}

class SideEffectProbe {
  calls = 0;

  constructor(
    private readonly store: RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>,
    private readonly fail = false,
    private readonly key = 'registration-finalize:lifecycle-1',
  ) {}

  async execute(): Promise<TestResponse> {
    this.calls += 1;
    const claimed = await this.store.read(this.key);
    if (
      claimed.kind !== 'present' ||
      claimed.value.kind !== 'router_ab_ed25519_yao_registration_side_effect_claim_v1' ||
      claimed.value.prepared.kind !== 'prepared_test_effect'
    ) {
      throw new Error('side effect ran before its durable claim');
    }
    if (this.fail) throw new Error('effect response lost');
    return { ok: true, receipt: 'wallet-session-receipt' };
  }
}

function bridgeRunInput(probe: SideEffectProbe) {
  return {
    kind: 'prepared_resumable' as const,
    operation: 'finalize' as const,
    key: 'registration-finalize:lifecycle-1',
    requestFingerprint: REQUEST_FINGERPRINT,
    resumeAfterMs: 1,
    nowMs: fixedNow,
    prepare: prepareTestEffect,
    derivePreparedArtifactFingerprint: deriveTestPreparedArtifactFingerprint,
    execute: probe.execute.bind(probe),
  };
}

function fixedNow(): number {
  return 1_725_000_000_000;
}

function fixedNowAfterResumeDelay(): number {
  return fixedNow() + 1;
}

function registrationCapabilityFixture() {
  const walletId = walletIdFromString('wallet-registration-bridge');
  return {
    walletId,
    fixture: buildEd25519YaoCapabilityFixture({
      walletId,
      nearAccountId: 'wallet-registration-bridge.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-registration-bridge',
      thresholdSessionId: 'threshold-registration-bridge',
      signerSlot: 1,
      signingWorkerId: 'signing-worker-bridge',
      participantIds: [1, 2],
      runtimePolicyScope: {
        orgId: 'org-registration-bridge',
        projectId: 'project-registration-bridge',
        envId: 'env-registration-bridge',
        signingRootVersion: 'root-registration-bridge-v1',
      },
      seed: 93,
    }),
  };
}

function pendingReceiptBoundaryFixture(): Record<string, unknown> {
  const walletId = walletIdFromString('wallet-registration-receipt-boundary');
  const rpIdResult = parseWebAuthnRpId('example.com');
  if (!rpIdResult.ok) throw new Error(rpIdResult.error.message);
  const credentialIdResult = parseWebAuthnCredentialIdB64u('credential-receipt-boundary');
  if (!credentialIdResult.ok) throw new Error(credentialIdResult.error.message);
  const authority: WalletAuthAuthority = buildPasskeyWalletAuthAuthority({
    walletId,
    rpId: rpIdResult.value,
    credentialIdB64u: credentialIdResult.value,
  });
  return {
    kind: 'wallet_registration_session_commit_receipt_v2',
    operation: 'registration_activate',
    operationFingerprint: REQUEST_FINGERPRINT,
    registrationCeremonyId: 'registration-receipt-boundary',
    walletId,
    walletAuthMethodId: authority.bindingId,
    authority,
    authMethod: {
      kind: 'passkey',
      credentialIdB64u: credentialIdResult.value,
      credentialPublicKeyB64u: 'credential-public-key-receipt-boundary',
    },
    expectedOrigin: 'https://app.example.com',
    registrationDiagnostics: {
      kind: 'wallet_registration_route_diagnostics_v1',
      route: 'wallets_register_finalize',
      entries: [
        { name: 'registrationIntentLoadMs', durationMs: 1 },
        { name: 'registrationAuthorityVerifyMs', durationMs: 2 },
        { name: 'registrationFinalizeReplayCacheMs', durationMs: 3 },
      ],
    },
    committed: {
      kind: 'near_pending',
      nearProvisioning: { status: 'near_pending' },
    },
  };
}

test.describe('registration side-effect persistence bridge', () => {
  test('claims before effects and replays the exact terminal response without repeating them', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'executed',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    expect(probe.calls).toBe(1);
  });

  test('stores only a credential-free receipt and rebuilds a fresh replay response', async () => {
    const store = new CredentialFreeRegistrationStore();
    let effectCalls = 0;
    const input = {
      kind: 'prepared_resumable' as const,
      operation: 'registration_activate' as const,
      key: 'registration-activate:credential-free',
      requestFingerprint: REQUEST_FINGERPRINT,
      resumeAfterMs: 1,
      nowMs: fixedNow,
      prepare: prepareTestEffect,
      derivePreparedArtifactFingerprint: deriveTestPreparedArtifactFingerprint,
      execute: async (): Promise<CredentialBearingResponse> => {
        effectCalls += 1;
        return {
          ok: true,
          committedIdentity: 'wallet-session-identity',
          walletSessionToken: 'first-ephemeral-token',
        };
      },
      projectReceipt: projectCredentialFreeTestReceipt,
      replay: replayCredentialFreeTestReceipt,
      adaptLegacyResponse: (response: CredentialBearingResponse) => response,
    };

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV2<
        CredentialBearingResponse,
        CredentialFreeReceipt,
        PreparedMarker
      >(store, input),
    ).resolves.toEqual({
      kind: 'executed',
      value: {
        ok: true,
        committedIdentity: 'wallet-session-identity',
        walletSessionToken: 'first-ephemeral-token',
      },
    });

    const stored = store.records.get(input.key);
    expect(stored?.value.kind).toBe('router_ab_ed25519_yao_registration_side_effect_completion_v2');
    expect(stored?.value).toMatchObject({
      receipt: {
        kind: 'credential_free_test_receipt',
        committedIdentity: 'wallet-session-identity',
      },
    });
    expect(JSON.stringify(stored?.value)).not.toContain('first-ephemeral-token');
    expect(JSON.stringify(stored?.value)).not.toContain('response');

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV2<
        CredentialBearingResponse,
        CredentialFreeReceipt,
        PreparedMarker
      >(store, input),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: {
        ok: true,
        committedIdentity: 'wallet-session-identity',
        walletSessionToken: 'replayed-ephemeral-token',
      },
    });
    expect(effectCalls).toBe(1);
  });

  test('reads a strict legacy completion row during the compatibility drain', async () => {
    const prepared = { kind: 'prepared_test_effect' } as const;
    const rawLegacy = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'registration_activate',
      requestFingerprint: REQUEST_FINGERPRINT,
      preparedArtifactFingerprint: await deriveTestPreparedArtifactFingerprint(prepared),
      claimedAtMs: fixedNow(),
      completedAtMs: fixedNow(),
      prepared,
      response: {
        ok: true,
        committedIdentity: 'legacy-committed-identity',
        walletSessionToken: 'legacy-persisted-token',
      },
    };
    const parsed = parseRouterAbEd25519YaoRegistrationSideEffectRecordV2WithLegacy(rawLegacy, {
      operation: 'registration_activate',
      parsePrepared: (value) =>
        value &&
        typeof value === 'object' &&
        (value as { kind?: unknown }).kind === 'prepared_test_effect'
          ? { kind: 'prepared_test_effect' }
          : null,
      parseReceipt: () => null,
      parseLegacyResponse: (value) => {
        if (!value || typeof value !== 'object') return null;
        const response = value as {
          ok?: unknown;
          committedIdentity?: unknown;
          walletSessionToken?: unknown;
        };
        return response.ok === true &&
          typeof response.committedIdentity === 'string' &&
          typeof response.walletSessionToken === 'string'
          ? {
              ok: true,
              committedIdentity: response.committedIdentity,
              walletSessionToken: response.walletSessionToken,
            }
          : null;
      },
    });
    expect(parsed?.kind).toBe('router_ab_ed25519_yao_registration_side_effect_completion_v1');
    if (!parsed || parsed.kind !== 'router_ab_ed25519_yao_registration_side_effect_completion_v1') {
      throw new Error('legacy completion did not parse');
    }
    const store = new CredentialFreeRegistrationStore();
    store.records.set('registration-activate:legacy-drain', {
      version: 1,
      value: parsed,
    });
    const input = {
      kind: 'prepared_resumable' as const,
      operation: 'registration_activate' as const,
      key: 'registration-activate:legacy-drain',
      requestFingerprint: REQUEST_FINGERPRINT,
      resumeAfterMs: 1,
      nowMs: fixedNow,
      prepare: prepareTestEffect,
      derivePreparedArtifactFingerprint: deriveTestPreparedArtifactFingerprint,
      execute: async (): Promise<CredentialBearingResponse> => {
        throw new Error('legacy completion must not execute');
      },
      projectReceipt: projectCredentialFreeTestReceipt,
      replay: replayCredentialFreeTestReceipt,
      adaptLegacyResponse: (response: CredentialBearingResponse) => response,
    };
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV2<
        CredentialBearingResponse,
        CredentialFreeReceipt,
        PreparedMarker
      >(store, input),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: {
        ok: true,
        committedIdentity: 'legacy-committed-identity',
        walletSessionToken: 'legacy-persisted-token',
      },
    });
  });

  test('parses the activation pending receipt with exact credential-free keys', async () => {
    const raw = pendingReceiptBoundaryFixture();
    const parsed = parseWalletRegistrationSessionCommitReceiptV2(raw, () => {
      throw new Error('pending receipts have no ready branch');
    });
    expect(parsed).toMatchObject({
      kind: 'wallet_registration_session_commit_receipt_v2',
      operation: 'registration_activate',
      committed: {
        kind: 'near_pending',
        nearProvisioning: { status: 'near_pending' },
      },
      registrationDiagnostics: {
        entries: [
          { name: 'registrationIntentLoadMs', durationMs: 1 },
          { name: 'registrationAuthorityVerifyMs', durationMs: 2 },
          { name: 'registrationFinalizeReplayCacheMs', durationMs: 3 },
        ],
      },
    });
    expect(JSON.stringify(parsed)).not.toContain('walletSessionToken');
  });

  test('persists deterministic terminal errors as credential-free replay receipts', async () => {
    const receipt = projectWalletRegistrationSessionCommitReceiptV2({
      operation: 'registration_activate',
      operationFingerprint: REQUEST_FINGERPRINT,
      registrationCeremonyId: 'registration-error-receipt',
      execution: {
        kind: 'unissued',
        response: {
          ok: false,
          code: 'invalid_registration_state',
          message: 'Registration cannot be activated from this state',
        },
      },
    });
    expect(
      parseWalletRegistrationSessionCommitReceiptV2(receipt, () => {
        throw new Error('error receipts have no signer branch');
      }),
    ).toEqual(receipt);
    expect(JSON.stringify(receipt)).not.toContain('walletSessionToken');
  });

  test('rejects credential-bearing receipts for activation and deferred NEAR branches', async () => {
    const activationRaw = pendingReceiptBoundaryFixture();
    const activationWithCredential = {
      ...activationRaw,
      committed: {
        ...activationRaw.committed,
        response: { walletSessionToken: 'persisted-bearer' },
      },
    };
    expect(
      parseWalletRegistrationSessionCommitReceiptV2(activationWithCredential, () => null),
    ).toBeNull();

    const deferredWithCredential = {
      ...activationRaw,
      operation: 'near_provisioning',
      committed: {
        kind: 'near_ready',
        nearProvisioning: { status: 'near_ready' },
        response: { primaryOperationCredential: 'persisted-credential' },
      },
    };
    expect(
      parseWalletRegistrationSessionCommitReceiptV2(deferredWithCredential, () => null),
    ).toBeNull();
  });

  test('leaves an uncertain claim durable and never retries an unknown effect', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    const probe = new SideEffectProbe(store, true);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'effect',
      message: 'effect response lost',
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toMatchObject({ kind: 'in_progress', prepared: { kind: 'prepared_test_effect' } });
    expect(probe.calls).toBe(1);
  });

  test('keeps retryable returned failures as resumable claims', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    const input = {
      kind: 'prepared_resumable' as const,
      operation: 'registration_start' as const,
      key: 'registration-start:retryable',
      requestFingerprint: REQUEST_FINGERPRINT,
      resumeAfterMs: 1,
      nowMs: fixedNow,
      prepare: prepareTestEffect,
      derivePreparedArtifactFingerprint: deriveTestPreparedArtifactFingerprint,
      execute: executeRetryableTestEffect,
    };

    await expect(runRouterAbEd25519YaoRegistrationSideEffectV1(store, input)).resolves.toEqual({
      kind: 'uncertain',
      phase: 'effect',
      message: 'runtime is temporarily unavailable',
    });
    await expect(store.read('registration-start:retryable')).resolves.toMatchObject({
      kind: 'present',
      value: { kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1' },
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, input),
    ).resolves.toMatchObject({ kind: 'in_progress' });
  });

  test('does not invoke an effect when the durable claim write throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    store.throwClaimPuts = 1;
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'claim',
      message: 'side-effect claim write unavailable',
    });
    expect(probe.calls).toBe(0);
  });

  test('does not invoke an effect when the initial claim read throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    store.throwReads = 1;
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'claim',
      message: 'side-effect read unavailable',
    });
    expect(probe.calls).toBe(0);
  });

  test('does not invoke an effect when a competing claim cannot be read back', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    const prepared = await prepareTestEffect();
    const claimWinner: RouterAbEd25519YaoRegistrationSideEffectClaimV1<PreparedMarker> = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
      operation: 'finalize',
      requestFingerprint: REQUEST_FINGERPRINT,
      preparedArtifactFingerprint: await deriveTestPreparedArtifactFingerprint(prepared),
      claimedAtMs: fixedNow(),
      prepared,
    };
    store.claimWinner = claimWinner;
    store.throwReadCalls.add(2);
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'claim',
      message: 'side-effect read unavailable',
    });
    expect(probe.calls).toBe(0);
  });

  test('does not repeat an effect after its terminal write throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    store.throwTerminalPuts = 1;
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'terminal_commit',
      message: 'side-effect terminal write unavailable',
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toMatchObject({ kind: 'in_progress', prepared: { kind: 'prepared_test_effect' } });
    expect(probe.calls).toBe(1);
  });

  test('replays a committed terminal winner after its first reconciliation read throws', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    const prepared = await prepareTestEffect();
    store.terminalWinner = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'finalize',
      requestFingerprint: REQUEST_FINGERPRINT,
      preparedArtifactFingerprint: await deriveTestPreparedArtifactFingerprint(prepared),
      claimedAtMs: fixedNow(),
      completedAtMs: fixedNow(),
      prepared,
      response: { ok: true, receipt: 'wallet-session-receipt' },
    };
    store.throwReadCalls.add(3);
    const probe = new SideEffectProbe(store);

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'terminal_commit',
      message: 'side-effect read unavailable',
    });
    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    expect(probe.calls).toBe(1);
  });

  test('reconciles an exact terminal winner after the effect response', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedMarker>();
    const probe = new SideEffectProbe(store);
    const prepared = await prepareTestEffect();
    const terminalWinner: RouterAbEd25519YaoRegistrationSideEffectCompletionV1<
      TestResponse,
      PreparedMarker
    > = {
      kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
      operation: 'finalize',
      requestFingerprint: REQUEST_FINGERPRINT,
      preparedArtifactFingerprint: await deriveTestPreparedArtifactFingerprint(prepared),
      claimedAtMs: fixedNow(),
      completedAtMs: fixedNow(),
      prepared,
      response: { ok: true, receipt: 'wallet-session-receipt' },
    };
    store.terminalWinner = terminalWinner;

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1(store, bridgeRunInput(probe)),
    ).resolves.toEqual({
      kind: 'exact_replay',
      value: { ok: true, receipt: 'wallet-session-receipt' },
    });
    expect(probe.calls).toBe(1);
  });

  test('reapplies only deterministic capability state after a shared CAS conflict', async () => {
    const delegate = createRegistrationBridgePartitionStore();
    const store = new OneConflictRegistrationBridgePartitionStore(delegate);
    const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
      signingWorkerId: 'signing-worker-bridge',
      store,
      registrationBackend: new UnavailableRouterAbEd25519YaoRegistrationBackend(),
    });
    const { walletId, fixture } = registrationCapabilityFixture();

    await expect(
      runtime.installPersistedActiveCapability(fixture.capability),
    ).resolves.toMatchObject({
      ok: true,
      disposition: 'installed',
    });
    await expect(
      runtime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId,
        nearEd25519SigningKeyId: 'near-ed25519-registration-bridge',
        signerSlot: 1,
        signingWorkerId: 'signing-worker-bridge',
        participantIds: [1, 2],
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(delegate.load('registration-fixture-93')).resolves.toMatchObject({
      state: {
        export: { authorizationNonces: new Set(['concurrent-winner']) },
      },
    });
  });

  test('rehydrates one existing-wallet capability from the canonical signer on a shared miss', async () => {
    const store = createRegistrationBridgePartitionStore();
    const { walletId, fixture } = registrationCapabilityFixture();
    let fallbackReads = 0;
    const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
      signingWorkerId: 'signing-worker-bridge',
      store,
      registrationBackend: new UnavailableRouterAbEd25519YaoRegistrationBackend(),
      loadPersistedActiveCapability: async () => {
        fallbackReads += 1;
        return fixture.capability;
      },
    });

    await expect(
      runtime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId,
        nearEd25519SigningKeyId: 'near-ed25519-registration-bridge',
        signerSlot: 1,
        signingWorkerId: 'signing-worker-bridge',
        participantIds: [1, 2],
      }),
    ).resolves.toMatchObject({ ok: true });
    expect(fallbackReads).toBe(1);
  });

  test('stops after one deterministic reconciliation when contention continues', async () => {
    const delegate = createRegistrationBridgePartitionStore();
    const store = new AlwaysConflictRegistrationBridgePartitionStore(delegate);
    const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
      signingWorkerId: 'signing-worker-bridge',
      store,
      registrationBackend: new UnavailableRouterAbEd25519YaoRegistrationBackend(),
    });
    const { fixture } = registrationCapabilityFixture();

    await expect(runtime.installPersistedActiveCapability(fixture.capability)).rejects.toThrow(
      'Request-scoped product state remained contended after one reconciliation',
    );
    expect(store.commitAttempts).toBe(2);
  });
});

test.describe('registration side-effect prepared artifacts', () => {
  type PreparedTx = { readonly transactionHash: string; readonly bytes: readonly number[] };

  const PREPARED_KEY = 'registration-finalize:lifecycle-prepared';

  function preparedRunInput(input: {
    readonly store: RegistrationSideEffectMemoryStore<TestResponse, PreparedTx>;
    readonly prepareCalls: { count: number };
    readonly broadcasts: PreparedTx[];
    readonly failEffect?: boolean;
    readonly nowMs?: () => number;
  }) {
    return {
      kind: 'prepared_resumable' as const,
      resumeAfterMs: 1,
      operation: 'finalize' as const,
      key: PREPARED_KEY,
      requestFingerprint: REQUEST_FINGERPRINT,
      nowMs: input.nowMs ?? fixedNow,
      prepare: async (): Promise<PreparedTx> => {
        input.prepareCalls.count += 1;
        // A rebuild would take a fresh nonce, so vary the hash per call.
        return {
          transactionHash: `tx-hash-${input.prepareCalls.count}`,
          bytes: [1, 2, input.prepareCalls.count],
        };
      },
      derivePreparedArtifactFingerprint: deriveTestPreparedArtifactFingerprint,
      execute: async (prepared: PreparedTx): Promise<TestResponse> => {
        const stored = await input.store.read(PREPARED_KEY);
        if (
          stored.kind !== 'present' ||
          stored.value.kind !== 'router_ab_ed25519_yao_registration_side_effect_claim_v1' ||
          !('prepared' in stored.value) ||
          stored.value.prepared.transactionHash !== prepared.transactionHash
        ) {
          throw new Error('broadcast ran before its transaction was durable');
        }
        input.broadcasts.push(prepared);
        if (input.failEffect) throw new Error('broadcast response lost');
        return { ok: true, receipt: prepared.transactionHash };
      },
    };
  }

  test('persists the signed transaction before the broadcast runs', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedTx>();
    const prepareCalls = { count: 0 };
    const broadcasts: PreparedTx[] = [];

    const result = await runRouterAbEd25519YaoRegistrationSideEffectV1<TestResponse, PreparedTx>(
      store,
      preparedRunInput({ store, prepareCalls, broadcasts }),
    );

    expect(result.kind).toBe('executed');
    expect(prepareCalls.count).toBe(1);
    expect(broadcasts).toHaveLength(1);
    expect(broadcasts[0]?.transactionHash).toBe('tx-hash-1');
  });

  test('an interrupted broadcast replays the persisted transaction instead of rebuilding it', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedTx>();
    const prepareCalls = { count: 0 };
    const broadcasts: PreparedTx[] = [];

    const lost = await runRouterAbEd25519YaoRegistrationSideEffectV1<TestResponse, PreparedTx>(
      store,
      preparedRunInput({ store, prepareCalls, broadcasts, failEffect: true }),
    );
    expect(lost.kind).toBe('uncertain');
    expect(prepareCalls.count).toBe(1);

    const resumed = await runRouterAbEd25519YaoRegistrationSideEffectV1<TestResponse, PreparedTx>(
      store,
      preparedRunInput({
        store,
        prepareCalls,
        broadcasts,
        nowMs: fixedNowAfterResumeDelay,
      }),
    );

    expect(resumed).toEqual({ kind: 'executed', value: { ok: true, receipt: 'tx-hash-1' } });
    // The second attempt must not build a second transaction.
    expect(prepareCalls.count).toBe(1);
    expect(broadcasts.map((entry) => entry.transactionHash)).toEqual(['tx-hash-1', 'tx-hash-1']);
  });

  test('a completed prepared effect replays its exact response without rebroadcasting', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedTx>();
    const prepareCalls = { count: 0 };
    const broadcasts: PreparedTx[] = [];

    await runRouterAbEd25519YaoRegistrationSideEffectV1<TestResponse, PreparedTx>(
      store,
      preparedRunInput({ store, prepareCalls, broadcasts }),
    );
    const replay = await runRouterAbEd25519YaoRegistrationSideEffectV1<TestResponse, PreparedTx>(
      store,
      preparedRunInput({ store, prepareCalls, broadcasts }),
    );

    expect(replay).toEqual({ kind: 'exact_replay', value: { ok: true, receipt: 'tx-hash-1' } });
    expect(prepareCalls.count).toBe(1);
    expect(broadcasts).toHaveLength(1);
    const persisted = await store.read(PREPARED_KEY);
    expect(persisted).toMatchObject({
      kind: 'present',
      value: {
        kind: 'router_ab_ed25519_yao_registration_side_effect_completion_v1',
        prepared: { transactionHash: 'tx-hash-1', bytes: [1, 2, 1] },
      },
    });
  });

  test('refuses a persisted artifact whose content no longer matches its fingerprint', async () => {
    const store = new RegistrationSideEffectMemoryStore<TestResponse, PreparedTx>();
    const prepareCalls = { count: 0 };
    const broadcasts: PreparedTx[] = [];

    await runRouterAbEd25519YaoRegistrationSideEffectV1<TestResponse, PreparedTx>(
      store,
      preparedRunInput({ store, prepareCalls, broadcasts, failEffect: true }),
    );
    const stored = store.records.get(PREPARED_KEY);
    if (
      !stored ||
      stored.value.kind !== 'router_ab_ed25519_yao_registration_side_effect_claim_v1'
    ) {
      throw new Error('expected a durable prepared claim');
    }
    store.records.set(PREPARED_KEY, {
      version: stored.version,
      value: {
        ...stored.value,
        prepared: { ...stored.value.prepared, bytes: [9, 9, 9] },
      },
    });

    await expect(
      runRouterAbEd25519YaoRegistrationSideEffectV1<TestResponse, PreparedTx>(
        store,
        preparedRunInput({
          store,
          prepareCalls,
          broadcasts,
          nowMs: fixedNowAfterResumeDelay,
        }),
      ),
    ).resolves.toEqual({
      kind: 'uncertain',
      phase: 'claim',
      message: 'registration side-effect prepared artifact fingerprint is invalid',
    });
    expect(prepareCalls.count).toBe(1);
    expect(broadcasts).toHaveLength(1);
  });
});

test.describe('ambiguous effects are never persisted as terminal', () => {
  type PreparedTx = { readonly transactionHash: string };
  type BroadcastResult = { readonly success: boolean };

  const KEY = 'registration-finalize:lifecycle-ambiguous';

  function ambiguousRunInput(input: {
    readonly prepareCalls: { count: number };
    readonly attempts: string[];
    readonly settleOnResume: boolean;
    readonly nowMs?: () => number;
  }) {
    return {
      kind: 'prepared_resumable' as const,
      resumeAfterMs: 1,
      operation: 'finalize' as const,
      key: KEY,
      requestFingerprint: REQUEST_FINGERPRINT,
      nowMs: input.nowMs ?? fixedNow,
      prepare: async (): Promise<PreparedTx> => {
        input.prepareCalls.count += 1;
        return { transactionHash: `tx-${input.prepareCalls.count}` };
      },
      derivePreparedArtifactFingerprint: deriveTestPreparedArtifactFingerprint,
      execute: async (
        prepared: PreparedTx,
        attempt: 'fresh' | 'resumed',
      ): Promise<BroadcastResult> => {
        input.attempts.push(attempt);
        if (attempt === 'resumed' && input.settleOnResume) return { success: true };
        // Production reports an unobservable outcome by throwing, so the claim
        // stays open instead of recording a transaction that may be on chain.
        throw new Error('RPC timed out after submission');
      },
    };
  }

  test('an unobservable broadcast leaves the claim open rather than recording failure', async () => {
    const store = new RegistrationSideEffectMemoryStore<BroadcastResult, PreparedTx>();
    const prepareCalls = { count: 0 };
    const attempts: string[] = [];

    const first = await runRouterAbEd25519YaoRegistrationSideEffectV1<BroadcastResult, PreparedTx>(
      store,
      ambiguousRunInput({ prepareCalls, attempts, settleOnResume: false }),
    );

    expect(first.kind).toBe('uncertain');
    const persisted = await store.read(KEY);
    expect(persisted.kind).toBe('present');
    if (persisted.kind === 'present') {
      // A completion here would replay a possibly-successful transaction as a
      // permanent failure on every later retry.
      expect(persisted.value.kind).toBe('router_ab_ed25519_yao_registration_side_effect_claim_v1');
    }
  });

  test('a resumed attempt is told it is resuming so it can reconcile', async () => {
    const store = new RegistrationSideEffectMemoryStore<BroadcastResult, PreparedTx>();
    const prepareCalls = { count: 0 };
    const attempts: string[] = [];

    await runRouterAbEd25519YaoRegistrationSideEffectV1<BroadcastResult, PreparedTx>(
      store,
      ambiguousRunInput({ prepareCalls, attempts, settleOnResume: false }),
    );
    const resumed = await runRouterAbEd25519YaoRegistrationSideEffectV1<
      BroadcastResult,
      PreparedTx
    >(
      store,
      ambiguousRunInput({
        prepareCalls,
        attempts,
        settleOnResume: true,
        nowMs: fixedNowAfterResumeDelay,
      }),
    );

    expect(resumed).toEqual({ kind: 'executed', value: { success: true } });
    expect(attempts).toEqual(['fresh', 'resumed']);
    expect(prepareCalls.count).toBe(1);
  });
});

test.describe('concurrent finalize contention', () => {
  type Prepared = { readonly hash: string };
  type Result = { readonly receipt: string };

  const KEY = 'registration-finalize:lifecycle-contended';

  function contendedRunInput(input: {
    readonly store: RegistrationSideEffectMemoryStore<Result, Prepared>;
    readonly effects: string[];
  }) {
    return {
      kind: 'prepared_resumable' as const,
      resumeAfterMs: 1,
      operation: 'finalize' as const,
      key: KEY,
      requestFingerprint: REQUEST_FINGERPRINT,
      nowMs: fixedNow,
      prepare: async (): Promise<Prepared> => ({ hash: 'tx-single' }),
      derivePreparedArtifactFingerprint: deriveTestPreparedArtifactFingerprint,
      execute: async (prepared: Prepared): Promise<Result> => {
        input.effects.push(prepared.hash);
        return { receipt: prepared.hash };
      },
    };
  }

  test('only one of two concurrent finalizes runs the effect', async () => {
    const store = new RegistrationSideEffectMemoryStore<Result, Prepared>();
    const effects: string[] = [];

    const [first, second] = await Promise.all([
      runRouterAbEd25519YaoRegistrationSideEffectV1<Result, Prepared>(
        store,
        contendedRunInput({ store, effects }),
      ),
      runRouterAbEd25519YaoRegistrationSideEffectV1<Result, Prepared>(
        store,
        contendedRunInput({ store, effects }),
      ),
    ]);

    // The claim is a create-if-absent CAS, so exactly one attempt owns the
    // effect. A second broadcast here would be a duplicate sponsored account.
    expect(effects).toHaveLength(1);
    const kinds = [first.kind, second.kind].sort();
    expect(kinds).toContain('executed');
    expect(kinds.filter((kind) => kind === 'in_progress' || kind === 'exact_replay')).toHaveLength(
      1,
    );
  });

  test('a losing concurrent finalize never reports success it did not perform', async () => {
    const store = new RegistrationSideEffectMemoryStore<Result, Prepared>();
    const effects: string[] = [];

    await runRouterAbEd25519YaoRegistrationSideEffectV1<Result, Prepared>(
      store,
      contendedRunInput({ store, effects }),
    );
    const loser = await runRouterAbEd25519YaoRegistrationSideEffectV1<Result, Prepared>(
      store,
      contendedRunInput({ store, effects }),
    );

    expect(loser).toEqual({ kind: 'exact_replay', value: { receipt: 'tx-single' } });
    expect(effects).toHaveLength(1);
  });

  test('only one stale-claim contender acquires the resume lease', async () => {
    const store = new RegistrationSideEffectMemoryStore<Result, Prepared>();
    const effects: string[] = [];
    const prepared = { hash: 'tx-single' };
    await store.put(
      KEY,
      {
        kind: 'router_ab_ed25519_yao_registration_side_effect_claim_v1',
        operation: 'finalize',
        requestFingerprint: REQUEST_FINGERPRINT,
        preparedArtifactFingerprint: await deriveTestPreparedArtifactFingerprint(prepared),
        claimedAtMs: fixedNow(),
        prepared,
      },
      null,
    );
    const resumedInput = {
      ...contendedRunInput({ store, effects }),
      nowMs: fixedNowAfterResumeDelay,
    };

    const [first, second] = await Promise.all([
      runRouterAbEd25519YaoRegistrationSideEffectV1<Result, Prepared>(store, resumedInput),
      runRouterAbEd25519YaoRegistrationSideEffectV1<Result, Prepared>(store, resumedInput),
    ]);

    expect(effects).toHaveLength(1);
    expect([first.kind, second.kind]).toContain('executed');
    expect(
      [first.kind, second.kind].filter((kind) => kind === 'in_progress' || kind === 'exact_replay'),
    ).toHaveLength(1);
  });
});
