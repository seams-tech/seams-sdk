import baseConfig from './playwright.intended.config';

const WEB_SERVER_READY_PORT =
  process.env.SEAMS_INTENDED_WEB_SERVER_READY_PORT || String(37_000 + (process.pid % 10_000));
process.env.SEAMS_INTENDED_WEB_SERVER_READY_PORT = WEB_SERVER_READY_PORT;
const WEB_SERVER_READY_URL =
  process.env.SEAMS_INTENDED_WEB_SERVER_READY_URL ||
  `http://127.0.0.1:${WEB_SERVER_READY_PORT}/readyz`;

export default {
  ...baseConfig,
  webServer: {
    command: 'node ./scripts/start-intended-services.mjs',
    url: WEB_SERVER_READY_URL,
    reuseExistingServer: false,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 30_000 },
    timeout: 1_800_000,
  },
};
