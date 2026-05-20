import type {
  ReadyEcdsaSignerSession,
  ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  EvmFamilyThresholdEcdsaEmailOtpSigning,
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaPasskeyReconnect,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import type { EvmFamilyThresholdReconnectRuntime } from './requireEvmFamilyStepUpAuth';

declare const readyMaterial: ReadyEvmFamilyEcdsaMaterial;
declare const signerSession: ReadyEcdsaSignerSession;
declare const operation: EvmFamilyThresholdEcdsaOperation;

void ({
  readyMaterial,
  signerSession,
  operation,
} satisfies EvmFamilyThresholdEcdsaReauthResult);

void ({
  readyMaterial,
  signerSession,
  // @ts-expect-error reauth results must not expose key-ref material
  keyRef: {},
  operation,
} satisfies EvmFamilyThresholdEcdsaReauthResult);

const missingReadyMaterial = {
  signerSession,
  operation,
};

// @ts-expect-error reauth results must carry canonical ready EVM-family material
void (missingReadyMaterial satisfies EvmFamilyThresholdEcdsaReauthResult);

const missingSignerSession = {
  readyMaterial,
  operation,
};

// @ts-expect-error reauth results must carry ready signer-session material
void (missingSignerSession satisfies EvmFamilyThresholdEcdsaReauthResult);

void ({
  complete: async () => ({ readyMaterial, signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaEmailOtpSigning);

void ({
  // @ts-expect-error Email OTP reauth completion must return ready material
  complete: async () => ({ signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaEmailOtpSigning);

void ({
  reconnect: async () => ({ readyMaterial, signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaPasskeyReconnect);

void ({
  // @ts-expect-error passkey reconnect must return ready material
  reconnect: async () => ({ signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaPasskeyReconnect);

void ({
  ensureThresholdEcdsaReadyMaterial: async () => ({
    readyMaterial,
    signerSession,
    operation,
  }),
} satisfies EvmFamilyThresholdReconnectRuntime);

void ({
  // @ts-expect-error threshold reconnect must return ready material
  ensureThresholdEcdsaReadyMaterial: async () => ({ signerSession, operation }),
} satisfies EvmFamilyThresholdReconnectRuntime);

export {};
