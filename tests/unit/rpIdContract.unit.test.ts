import { expect, test } from '@playwright/test';
import { buildConfigsFromEnv, PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import {
  SEAMS_LOCAL_DEVELOPMENT_RP_IDS,
  SEAMS_PRODUCTION_ASSOCIATED_DOMAIN,
  SEAMS_PRODUCTION_RP_ID,
} from '@/core/platform/ios/rpIdContract';

test.describe('RP ID contract', () => {
  test('records seams.sh as the production web and iOS RP ID', () => {
    expect(SEAMS_PRODUCTION_RP_ID).toBe('seams.sh');
    expect(SEAMS_PRODUCTION_ASSOCIATED_DOMAIN).toBe('webcredentials:seams.sh');
  });

  test('keeps local development on current localhost RP ID defaults', () => {
    const defaultRpId = PASSKEY_MANAGER_DEFAULT_CONFIGS.wallet.iframe.rpIdOverride;

    expect(SEAMS_LOCAL_DEVELOPMENT_RP_IDS).toContain(defaultRpId);
    expect(defaultRpId).not.toBe(SEAMS_PRODUCTION_RP_ID);
  });

  test('allows production deployments to opt into the shared seams.sh RP ID', () => {
    const configs = buildConfigsFromEnv({
      relayer: { url: 'https://relay.seams.sh' },
      iframeWallet: {
        walletOrigin: 'https://seams.sh',
        rpIdOverride: SEAMS_PRODUCTION_RP_ID,
      },
    });

    expect(configs.wallet.iframe.rpIdOverride).toBe(SEAMS_PRODUCTION_RP_ID);
  });
});
