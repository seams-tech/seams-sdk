import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '../../shared/src/utils/encoders';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';

const TEST_RUNTIME_SCOPE = { orgId: 'org-alpha', projectId: 'project-alpha', envId: 'env-alpha' } as const;

test.describe('threshold-ecdsa integrated key store', () => {
  test('persists relayer backend signer input without export-capable secret material', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});

    const bootstrap = await svc.bootstrapEcdsaFromRegistrationMaterial({
      userId: 'alice.near',
      rpId: 'wallet.example.test',
      clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(11)).toString('base64url'),
      sessionPolicy: {
        version: 'threshold_session_v1',
        userId: 'alice.near',
        rpId: 'wallet.example.test',
        sessionId: 'ecdsa-session-1',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 5,
        participantIds: [1, 2],
      },
    });

    expect(bootstrap.ok).toBe(true);
    const ecdsaThresholdKeyId = String((bootstrap as any).ecdsaThresholdKeyId || '').trim();
    expect(ecdsaThresholdKeyId).not.toBe('');

    const integratedKeyRecord = await (svc as any).getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId);
    expect(integratedKeyRecord).toBeTruthy();
    expect(integratedKeyRecord.ecdsaThresholdKeyId).toBe(ecdsaThresholdKeyId);
    expect(integratedKeyRecord.relayerRootShare32B64u).toBeTruthy();
    expect(base64UrlDecode(integratedKeyRecord.relayerRootShare32B64u)).toHaveLength(32);
    expect(integratedKeyRecord.relayerBackendInputB64u).toBeTruthy();
    expect(base64UrlDecode(integratedKeyRecord.relayerBackendInputB64u)).toHaveLength(32);
    expect(integratedKeyRecord.thresholdEcdsaPublicKeyB64u).toBeTruthy();
    expect(integratedKeyRecord.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
    expect(integratedKeyRecord.signingRootId).toBe(
      `${TEST_RUNTIME_SCOPE.projectId}:${TEST_RUNTIME_SCOPE.envId}`,
    );
    expect(integratedKeyRecord.signingRootVersion).toBeUndefined();
    expect(integratedKeyRecord.walletKeyVersion).toBe('v1');
    expect(integratedKeyRecord.derivationVersion).toBe(1);

    expect('canonical_x32_b64u' in integratedKeyRecord).toBe(false);
    expect('privateKeyHex' in integratedKeyRecord).toBe(false);
    expect('exportPrivateKeyHex' in integratedKeyRecord).toBe(false);
    expect('yClient32LeB64u' in integratedKeyRecord).toBe(false);
    expect('yRelayer32LeB64u' in integratedKeyRecord).toBe(false);
  });
});
