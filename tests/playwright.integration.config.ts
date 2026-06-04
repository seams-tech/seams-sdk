import baseConfig from './playwright.config';

export default {
  ...baseConfig,
  testMatch: [
    '**/unit/seamsWeb.chainSigners.integration.test.ts',
    '**/unit/signingVectors.webWasmReplay.integration.test.ts',
    '**/unit/thresholdEcdsa.tempoHighLevel.integration.test.ts',
    '**/unit/touchConfirm.workerRouter.integration.test.ts',
  ],
};
