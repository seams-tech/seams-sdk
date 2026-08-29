import { createWarmSessionStatusReader } from './helpers/warmSessionUiConfirm.fixtures';
import { expect, test } from '@playwright/test';
import {
  deriveEd25519CapabilityState,
  normalizeWarmSessionReadPorts,
  readWarmSessionClaims,
  resolveEcdsaSealTransport,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from '@/core/signingEngine/session/warmCapabilities/readModel';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import {
  buildEmailOtpEcdsaSealedRuntimeRecordFixture,
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { canonicalEcdsaAvailableLane } from './helpers/availableSigningLanes.fixtures';

/** Manifest plus the sealed record that correlates with it, resolved through
 * production correlation rather than assembled by hand. */
function resolvedEcdsaRuntime() {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: toWalletId(String(manifest.signer.walletId)),
    chainTarget: record.ecdsaRestore.chainTarget,
    sealedRecords: [record],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`sealed runtime fixture did not resolve: ${resolution.reason}`);
  }
  return { manifest, runtime: resolution.runtime };
}

test.describe('warmSessionReadModel', () => {
  test('maps warm-session status results into canonical claim states', () => {
    expect(
      toWarmSessionClaimFromStatusResult({
        thresholdSessionId: 'warm-session',
        status: {
          ok: true,
          remainingUses: 3,
          expiresAtMs: 1234,
        },
      }),
    ).toMatchObject({
      state: 'warm',
      thresholdSessionId: 'warm-session',
      remainingUses: 3,
      expiresAtMs: 1234,
    });

    expect(
      toWarmSessionClaimFromStatusResult({
        thresholdSessionId: 'missing-session',
        status: {
          ok: false,
          code: 'not_found',
          message: 'missing',
        },
      }),
    ).toMatchObject({
      state: 'missing',
      thresholdSessionId: 'missing-session',
    });

    expect(
      toWarmSessionClaimFromStatusResult({
        thresholdSessionId: 'unavailable-session',
        status: {
          ok: false,
          code: 'worker_error',
          message: 'worker down',
        },
      }),
    ).toMatchObject({
      state: 'unavailable',
      thresholdSessionId: 'unavailable-session',
      code: 'worker_error',
    });
  });

  test('uses batch warm-session status reads when available', async () => {
    let batchCalls = 0;
    let singleReads = 0;
    const touchConfirm = normalizeWarmSessionReadPorts({
      getWarmSessionStatus: async () => {
        singleReads += 1;
        return { ok: false, code: 'worker_error', message: 'should not be called' };
      },
      getWarmSessionStatuses: async ({ thresholdSessionIds }) => {
        batchCalls += 1;
        return {
          results: thresholdSessionIds.map((thresholdSessionId) => ({
            thresholdSessionId,
            result:
              thresholdSessionId === 'warm-session'
                ? {
                    ok: true as const,
                    remainingUses: 2,
                    expiresAtMs: 999,
                  }
                : {
                    ok: false as const,
                    code: 'not_found',
                    message: 'missing',
                  },
          })),
        };
      },
    });
    const claims = await readWarmSessionClaims({
      touchConfirm,
      thresholdSessionIds: ['warm-session', 'missing-session'],
    });

    expect(batchCalls).toBe(1);
    expect(singleReads).toBe(0);
    expect(claims.get('warm-session')).toMatchObject({
      state: 'warm',
      thresholdSessionId: 'warm-session',
      remainingUses: 2,
    });
    expect(claims.get('missing-session')).toMatchObject({
      state: 'missing',
      thresholdSessionId: 'missing-session',
    });
  });

  test('derives Ed25519 state from exact runtime, independent authorization, and claim', () => {
    const record = buildPasskeyEd25519SealedSessionRecordFixture();
    const runtime = parseExactEd25519SealedSessionRuntime(record);
    if (!runtime) throw new Error('expected exact Ed25519 runtime fixture');
    const auth = buildPasskeyEd25519AuthorizationProjectionFixture(record);

    expect(
      deriveEd25519CapabilityState({
        runtime,
        auth,
        prfClaim: {
          state: 'warm',
          thresholdSessionId: runtime.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: runtime.expiresAtMs,
        },
      }),
    ).toBe('ready');
    expect(
      deriveEd25519CapabilityState({
        runtime,
        auth,
        prfClaim: {
          state: 'unavailable',
          thresholdSessionId: runtime.thresholdSessionId,
          code: 'worker_error',
        },
      }),
    ).toBe('prf_unavailable');
    expect(
      deriveEd25519CapabilityState({
        runtime,
        auth: null,
        prfClaim: {
          state: 'warm',
          thresholdSessionId: runtime.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: runtime.expiresAtMs,
        },
      }),
    ).toBe('authorization_required');
  });

  test('resolves ECDSA seal transport from the sealed runtime and active authorization', () => {
    const { runtime } = resolvedEcdsaRuntime();
    const authorization = canonicalEcdsaAvailableLane({
      walletId: String(runtime.walletId),
      chainTarget: runtime.chainTarget,
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
      authMethod: 'email_otp',
    }).authorization;

    expect(
      resolveEcdsaSealTransport({
        runtime,
        auth: authorization,
        signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
          'signing-session-seal-kek-2026-02-r1',
        ),
      }),
    ).toMatchObject({
      curve: 'ecdsa',
      // Transport identity is the runtime's; the bearer proof is the Wallet
      // Session's. The two halves are read from their own owners, and no grant
      // is carried: a grant is a distinct identity from a Wallet Session and
      // the authorization boundary has none to give.
      walletId: String(runtime.walletId),
      chainTarget: runtime.chainTarget,
      relayerUrl: runtime.relayerUrl,
      walletSessionToken: authorization.operationCredential.token,
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
        'signing-session-seal-kek-2026-02-r1',
      ),
    });
  });

  test('withholds Email OTP ECDSA seal transport without an active Wallet Session', () => {
    const { runtime } = resolvedEcdsaRuntime();
    expect(runtime.authBinding.kind).toBe('email_otp');

    // An Email-OTP-bound runtime has no standing authorization of its own, so
    // with no live Wallet Session there is nothing to seal against.
    expect(
      resolveEcdsaSealTransport({
        runtime,
        auth: null,
      }),
    ).toBeNull();
  });

  test('maps unavailable claims into unavailable signing-session status', () => {
    expect(
      toSigningSessionStatus({
        sessionId: 'status-unavailable-session',
        claim: {
          state: 'unavailable',
          sessionId: 'status-unavailable-session',
          code: 'worker_error',
        },
      }),
    ).toMatchObject({
      sessionId: 'status-unavailable-session',
      status: 'unavailable',
      statusCode: 'worker_error',
    });
  });
});
