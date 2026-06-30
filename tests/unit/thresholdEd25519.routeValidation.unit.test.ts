import { expect, test } from '@playwright/test';
import {
  parseThresholdEd25519HssFinalizeWithSessionRouteRequest,
  parseThresholdEd25519SessionRouteRequest,
} from '../../packages/sdk-server-ts/src/router/thresholdEd25519RequestValidation';

function validThresholdEd25519SessionBody(): Record<string, unknown> {
  return {
    relayerKeyId: 'ed25519:relayer',
    sessionKind: 'jwt',
    sessionPolicy: {
      version: 'threshold_session_v1',
      walletId: 'frost-vermillion-k7p9m2',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'frost-vermillion-k7p9m2',
      rpId: 'localhost',
      relayerKeyId: 'ed25519:relayer',
      thresholdSessionId: 'tsess-route-validation',
      signingGrantId: 'grant-route-validation',
      ttlMs: 300_000,
      remainingUses: 1,
    },
  };
}

test('threshold-ed25519 session route rejects body-owned app session claims', () => {
  const parsed = parseThresholdEd25519SessionRouteRequest({
    ...validThresholdEd25519SessionBody(),
    appSessionClaims: {
      kind: 'app_session_v1',
      sub: 'frost-vermillion-k7p9m2',
      appSessionVersion: '1',
    },
  });

  expect(parsed.ok).toBe(false);
  if (!parsed.ok) {
    expect(parsed.body.message).toContain('Unsupported threshold-ed25519 session field');
    expect(parsed.body.message).toContain('appSessionClaims');
  }
});

test('threshold-ed25519 session route rejects body-owned expected origin', () => {
  const parsed = parseThresholdEd25519SessionRouteRequest({
    ...validThresholdEd25519SessionBody(),
    expected_origin: 'http://localhost',
  });

  expect(parsed.ok).toBe(false);
  if (!parsed.ok) {
    expect(parsed.body.message).toContain('Unsupported threshold-ed25519 session field');
    expect(parsed.body.message).toContain('expected_origin');
  }
});

test('threshold-ed25519 session route rejects body-owned ECDSA session claims', () => {
  const parsed = parseThresholdEd25519SessionRouteRequest({
    ...validThresholdEd25519SessionBody(),
    ecdsaSessionClaims: {
      kind: 'router_ab_ecdsa_hss_wallet_session_v1',
      walletId: 'frost-vermillion-k7p9m2',
    },
  });

  expect(parsed.ok).toBe(false);
  if (!parsed.ok) {
    expect(parsed.body.message).toContain('Unsupported threshold-ed25519 session field');
    expect(parsed.body.message).toContain('ecdsaSessionClaims');
  }
});

test('threshold-ed25519 HSS finalize requires server finalize output', () => {
  const parsed = parseThresholdEd25519HssFinalizeWithSessionRouteRequest({
    ceremonyHandle: 'ceremony-1',
    evaluationResult: {
      contextBindingB64u: 'context-binding',
      stagedEvaluatorArtifactB64u: 'staged-artifact',
    },
  });

  expect(parsed.ok).toBe(false);
  if (!parsed.ok) {
    expect(parsed.body).toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'serverEvalFinalizeOutputB64u is required',
    });
  }
});
