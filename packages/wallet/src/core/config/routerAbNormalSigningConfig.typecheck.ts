import type { RouterAbNormalSigningConfig, SeamsConfigsInput } from '../types/seams';

const disabledInput: SeamsConfigsInput = {
  routerAb: {
    normalSigning: {
      mode: 'disabled',
    },
  },
};

const enabledInput: SeamsConfigsInput = {
  routerAb: {
    normalSigning: {
      mode: 'enabled',
      signingWorkerId: 'local-signing-worker',
    },
  },
};

const disabledResolved: RouterAbNormalSigningConfig = {
  mode: 'disabled',
};

const enabledResolved: RouterAbNormalSigningConfig = {
  mode: 'enabled',
  signingWorkerId: 'local-signing-worker',
};

// @ts-expect-error enabled Router A/B normal signing requires a SigningWorker id.
const missingSigningWorkerId: RouterAbNormalSigningConfig = {
  mode: 'enabled',
};

const disabledWithSigningWorkerId: SeamsConfigsInput = {
  routerAb: {
    normalSigning: {
      mode: 'disabled',
      // @ts-expect-error disabled Router A/B normal signing cannot carry a SigningWorker id.
      signingWorkerId: 'local-signing-worker',
    },
  },
};

void disabledInput;
void enabledInput;
void disabledResolved;
void enabledResolved;
void missingSigningWorkerId;
void disabledWithSigningWorkerId;
