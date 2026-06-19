import { expect, test } from '@playwright/test';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import { resolveRouterAbEd25519ExportWalletSessionAuthFromRecord } from '@/core/signingEngine/flows/recovery/nearEd25519ExportFlow';

function makeRecord(
  overrides: Partial<ThresholdEd25519SessionRecord> = {},
): ThresholdEd25519SessionRecord {
  return {
    nearAccountId: 'alice.testnet' as any,
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
    walletSigningSessionId: 'wsess-export-ed25519',
    walletSessionJwt: 'router-ab-ed25519-wallet-session-jwt',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 2,
    updatedAtMs: Date.now(),
    source: 'registration',
    ...overrides,
  };
}

test.describe('near Ed25519 export Wallet Session auth', () => {
  test('does not require normal-signing material handles for single-key HSS export', () => {
    const result = resolveRouterAbEd25519ExportWalletSessionAuthFromRecord(makeRecord());

    expect(result).toMatchObject({
      ok: true,
      value: {
        kind: 'router_ab_ed25519_export_wallet_session_auth_v1',
        walletSessionJwt: 'router-ab-ed25519-wallet-session-jwt',
        thresholdSessionId: 'tsess-export-ed25519',
        walletSigningSessionId: 'wsess-export-ed25519',
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
