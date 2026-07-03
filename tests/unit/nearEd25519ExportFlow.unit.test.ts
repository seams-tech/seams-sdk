import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
} from '@shared/utils/signingSessionSeal';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import { resolveRouterAbEd25519ExportWalletSessionAuthFromRecord } from '@/core/signingEngine/flows/recovery/nearEd25519ExportFlow';

function makeTestJwt(payload: Record<string, unknown>): string {
  return [
    base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'none', typ: 'JWT' }))),
    base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload))),
    'signature',
  ].join('.');
}

function makeRecord(
  overrides: Partial<ThresholdEd25519SessionRecord> = {},
): ThresholdEd25519SessionRecord {
  const record = {
    walletId: walletIdFromString('alice-wallet'),
    nearAccountId: 'alice.testnet' as any,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('alice-key-scope'),
    rpId: 'localhost',
    relayerUrl: 'https://localhost:9444',
    relayerKeyId: 'ed25519:relayer-key',
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org-export',
      projectId: 'project-export',
      envId: 'dev',
      signingRootVersion: 'default',
    },
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-local',
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'tsess-export-ed25519',
    signingGrantId: 'wsess-export-ed25519',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 2,
    updatedAtMs: Date.now(),
    source: 'registration',
    ...overrides,
  };
  return {
    ...record,
    walletSessionJwt:
      overrides.walletSessionJwt ??
      makeTestJwt({
        kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
        walletId: record.walletId,
        nearAccountId: record.nearAccountId,
        nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
        thresholdSessionId: record.thresholdSessionId,
        signingGrantId: record.signingGrantId,
      }),
  };
}

test.describe('near Ed25519 export Wallet Session auth', () => {
  test('does not require normal-signing material handles for single-key HSS export', () => {
    const result = resolveRouterAbEd25519ExportWalletSessionAuthFromRecord(makeRecord());

    expect(result).toMatchObject({
      ok: true,
      value: {
        kind: 'router_ab_ed25519_export_wallet_session_auth_v1',
        thresholdSessionId: 'tsess-export-ed25519',
        signingGrantId: 'wsess-export-ed25519',
        signingWorkerId: 'signing-worker-local',
      },
    });
  });

  test('rejects records without Router A/B Wallet Session JWT auth', () => {
    const result = resolveRouterAbEd25519ExportWalletSessionAuthFromRecord(
      makeRecord({ walletSessionJwt: '' }),
    );

    expect(result).toEqual({ ok: false, reason: 'missing_wallet_session_jwt' });
  });
});
