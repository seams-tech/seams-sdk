import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '../../shared/src/utils/encoders';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdEd25519TestUtils';

const TEST_RUNTIME_SCOPE = {
  orgId: 'org-alpha',
  projectId: 'project-alpha',
  envId: 'env-alpha',
  signingRootVersion: 'root-v1',
} as const;
const TEST_ECDSA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
} as const;

test.describe('threshold-ecdsa integrated key store', () => {
  test('persists relayer backend signer input without export-capable secret material', async () => {
    const { svc } = createThresholdSigningServiceForUnitTests({});

    const bootstrap = await svc.bootstrapEcdsaFromRegistrationMaterial({
      walletSessionUserId: 'alice.near',
      rpId: 'wallet.example.test',
      clientRootShare32B64u: Buffer.from(new Uint8Array(32).fill(11)).toString('base64url'),
      sessionPolicy: {
        version: 'threshold_session_v1',
        walletSessionUserId: 'alice.near',
        subjectId: 'alice.near',
        rpId: 'wallet.example.test',
        chainTarget: TEST_ECDSA_CHAIN_TARGET,
        sessionId: 'ecdsa-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
        ttlMs: 60_000,
        remainingUses: 5,
        participantIds: [1, 2],
      },
    });

    expect(bootstrap.ok).toBe(true);
    const ecdsaThresholdKeyId = String((bootstrap as any).ecdsaThresholdKeyId || '').trim();
    expect(ecdsaThresholdKeyId).not.toBe('');
    const keyHandle = String((bootstrap as any).keyHandle || '').trim();
    expect(keyHandle).not.toBe('');

    const integratedKeyRecord = await (svc as any).getEcdsaIntegratedKeyRecordByKeyHandle(
      keyHandle,
    );
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
    expect(integratedKeyRecord.signingRootVersion).toBe(TEST_RUNTIME_SCOPE.signingRootVersion);
    expect(integratedKeyRecord.walletKeyVersion).toBe('v1');
    expect(integratedKeyRecord.derivationVersion).toBe(1);

    expect('canonical_x32_b64u' in integratedKeyRecord).toBe(false);
    expect('privateKeyHex' in integratedKeyRecord).toBe(false);
    expect('exportPrivateKeyHex' in integratedKeyRecord).toBe(false);
    expect('yClient32LeB64u' in integratedKeyRecord).toBe(false);
    expect('yRelayer32LeB64u' in integratedKeyRecord).toBe(false);
  });
});
