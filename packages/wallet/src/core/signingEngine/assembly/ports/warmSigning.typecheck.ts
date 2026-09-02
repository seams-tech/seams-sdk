import type { WarmSigningPorts } from './warmSigning';

declare const getWarmSessionStatus: WarmSigningPorts['statusUiConfirm']['getWarmSessionStatus'];

const displayOnlyStatusDeps: WarmSigningPorts['statusUiConfirm'] = {
  getWarmSessionStatus,
};

void displayOnlyStatusDeps;

const displayOnlyDepsWithPrompt: WarmSigningPorts['statusUiConfirm'] = {
  getWarmSessionStatus,
  // @ts-expect-error Display-only status reads cannot carry prompt-capable ports.
  touchIdPrompt: {},
};

void displayOnlyDepsWithPrompt;

const displayOnlyDepsWithClaim: WarmSigningPorts['statusUiConfirm'] = {
  getWarmSessionStatus,
  // @ts-expect-error Display-only status reads cannot claim warm-session material.
  claimWarmSessionMaterial: async () => ({
    ok: false,
    code: 'not_found',
    message: 'not found',
  }),
};

void displayOnlyDepsWithClaim;
