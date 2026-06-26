import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

function makeService(): AuthService {
  return new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
  });
}

test('link-device prepare is disabled before legacy threshold ECDSA bootstrap handling', async () => {
  const request: Parameters<AuthService['prepareLinkDevice']>[0] = {
    threshold_ecdsa: { client_root_share32_b64u: 'raw-root-share' },
  };
  const result = await makeService().prepareLinkDevice(request);

  expect(result).toMatchObject({
    ok: false,
    code: 'unsupported',
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(String(result.message || '')).toContain(
    'Linked-device lane creation is disabled until refactor 84 lands',
  );
});

test('email-recovery prepare rejects raw threshold ECDSA bootstrap payloads before setup work', async () => {
  const request: Parameters<AuthService['prepareEmailRecovery']>[0] = {
    // @ts-expect-error raw threshold_ecdsa is intentionally outside the typed boundary.
    threshold_ecdsa: { client_root_share32_b64u: 'raw-root-share' },
  };
  const result = await makeService().prepareEmailRecovery(request);

  expect(result).toMatchObject({
    ok: false,
    code: 'invalid_body',
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(String(result.message || '')).toContain(
    'threshold_ecdsa email-recovery bootstrap has been removed',
  );
});
