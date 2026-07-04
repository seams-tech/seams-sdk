import baseConfig from './playwright.intended.config';

const WEB_SERVER_READY_URL =
  process.env.SEAMS_INTENDED_WEB_SERVER_READY_URL || 'http://127.0.0.1:37888/readyz';

export default {
  ...baseConfig,
  webServer: {
    command: 'node ./scripts/start-intended-services.mjs',
    url: WEB_SERVER_READY_URL,
    reuseExistingServer: false,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 30_000 },
    timeout: 240_000,
  },
};
