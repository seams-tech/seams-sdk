import { createWarmSessionStatusReader } from './helpers/warmSessionUiConfirm.fixtures';
import { expect, test } from '@playwright/test';
import {
  deriveEd25519CapabilityState,
  normalizeWarmSessionReadPorts,
  readWarmSessionClaims,
  resolveEcdsaSealTransport,
  resolveEd25519AuthMaterial,
  toSigningSessionStatus,
  toWarmSessionClaimFromStatusResult,
} from '@/core/signingEngine/session/warmCapabilities/readModel';

import {
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  createThresholdEcdsaStoreFixture,
} from './helpers/signingSessionRecord.fixtures';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  activeEvmFamilyWalletSessionAuthorizationFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
        sessionId: 'warm-session',
        status: {
          ok: true,
          remainingUses: 3,
          expiresAtMs: 1234,
        },
      }),
    ).toMatchObject({
      state: 'warm',
      sessionId: 'warm-session',
      remainingUses: 3,
      expiresAtMs: 1234,
    });

    expect(
      toWarmSessionClaimFromStatusResult({
        sessionId: 'missing-session',
        status: {
          ok: false,
          code: 'not_found',
          message: 'missing',
        },
      }),
    ).toMatchObject({
      state: 'missing',
      sessionId: 'missing-session',
    });

    expect(
      toWarmSessionClaimFromStatusResult({
        sessionId: 'unavailable-session',
        status: {
          ok: false,
          code: 'worker_error',
          message: 'worker down',
        },
      }),
    ).toMatchObject({
      state: 'unavailable',
      sessionId: 'unavailable-session',
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
      getWarmSessionStatuses: async ({ sessionIds }) => {
        batchCalls += 1;
        return {
          results: sessionIds.map((sessionId) => ({
            sessionId,
            result:
              sessionId === 'warm-session'
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
      sessionIds: ['warm-session', 'missing-session'],
    });

    expect(batchCalls).toBe(1);
    expect(singleReads).toBe(0);
    expect(claims.get('warm-session')).toMatchObject({
      state: 'warm',
      sessionId: 'warm-session',
      remainingUses: 2,
    });
    expect(claims.get('missing-session')).toMatchObject({
      state: 'missing',
      sessionId: 'missing-session',
    });
  });

  // Ed25519 auth material stays record-owned. The ECDSA half of this pairing is
  // gone: ECDSA authorization is the reusable Wallet Session, not a record
  // field, so there is no ECDSA auth material to resolve from a record and no
  // cross-curve fallback left to rule out.
  test('resolves Ed25519 auth material from its own record', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'auth.testnet',
      thresholdSessionId: 'ed-wallet-session',
      walletSessionJwt: 'jwt:ed-wallet-session',
    });

    expect(resolveEd25519AuthMaterial(ed25519Record)).toMatchObject({
      capability: 'ed25519',
      walletSessionJwt: ed25519Record.walletSessionJwt,
      walletSessionJwtSource: 'ed25519_record',
    });
  });

  test('derives ready state from runtime-validated material before claim state', () => {
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'derive.testnet',
      thresholdSessionId: 'derive-ed25519-session',
      walletSessionJwt: 'jwt:derive-ed25519-session',
    });
    const unavailableRecord = seedEd25519WarmSessionRecord({
      nearAccountId: 'derive-unavailable.testnet',
      thresholdSessionId: 'derive-unavailable-ed25519-session',
      walletSessionJwt: 'jwt:derive-unavailable-ed25519-session',
    });

    expect(
      deriveEd25519CapabilityState({
        record: ed25519Record,
        auth: resolveEd25519AuthMaterial(ed25519Record),
        prfClaim: {
          state: 'warm',
          sessionId: ed25519Record.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: ed25519Record.expiresAtMs,
        },
      }),
    ).toBe('ready');

    expect(
      deriveEd25519CapabilityState({
        record: unavailableRecord,
        auth: resolveEd25519AuthMaterial(unavailableRecord),
        prfClaim: {
          state: 'unavailable',
          sessionId: unavailableRecord.thresholdSessionId,
          code: 'worker_error',
        },
      }),
    ).toBe('ready');
  });

  test('derives invalid for Ed25519 records missing Router A/B state', () => {
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'missing-router-ab-ed25519.testnet',
      thresholdSessionId: 'missing-router-ab-ed25519-session',
      walletSessionJwt: 'jwt:missing-router-ab-ed25519-session',
    });
    delete ed25519Record.routerAbNormalSigning;

    expect(
      deriveEd25519CapabilityState({
        record: ed25519Record,
        auth: resolveEd25519AuthMaterial(ed25519Record),
        prfClaim: {
          state: 'warm',
          sessionId: ed25519Record.thresholdSessionId,
          remainingUses: 4,
          expiresAtMs: ed25519Record.expiresAtMs,
        },
      }),
    ).toBe('invalid');
  });

  test('derives auth_missing for cookie passkey Ed25519 state without Wallet Session auth', () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'cookie-record-backed.testnet',
      thresholdSessionId: 'cookie-record-backed-session',
      thresholdSessionKind: 'cookie',
    });

    expect(
      deriveEd25519CapabilityState({
        record: ed25519Record,
        auth: resolveEd25519AuthMaterial(ed25519Record),
        prfClaim: {
          state: 'missing',
          sessionId: ed25519Record.thresholdSessionId,
        },
      }),
    ).toBe('auth_missing');
  });

  test('resolves ECDSA seal transport from the sealed runtime and active authorization', () => {
    const { runtime, manifest } = resolvedEcdsaRuntime();
    const authorization = activeEvmFamilyWalletSessionAuthorizationFixture({ manifest });

    expect(
      resolveEcdsaSealTransport({
        runtime,
        auth: authorization,
        signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
          'signing-session-seal-kek-2026-02-r1',
        ),
        shamirPrimeB64u: 'AQAB',
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
      walletSessionJwt: String(authorization.projection.walletSessionJwt),
      walletSessionJwtSource: 'ecdsa',
      signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
        'signing-session-seal-kek-2026-02-r1',
      ),
      shamirPrimeB64u: 'AQAB',
    });
  });

  test('withholds Email OTP ECDSA seal transport without an active Wallet Session', () => {
    const { runtime, manifest } = resolvedEcdsaRuntime();
    expect(runtime.authBinding.kind).toBe('email_otp');

    // An Email-OTP-bound runtime has no standing authorization of its own, so
    // with no live Wallet Session there is nothing to seal against.
    expect(
      resolveEcdsaSealTransport({
        runtime,
        auth: null,
        shamirPrimeB64u: 'AQAB',
      }),
    ).toBeNull();

    // An authorization present but carrying no JWT is the same absence.
    expect(
      resolveEcdsaSealTransport({
        runtime,
        auth: activeEvmFamilyWalletSessionAuthorizationFixture({
          manifest,
          walletSessionJwt: '',
        }),
        shamirPrimeB64u: 'AQAB',
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
