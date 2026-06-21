import type {
  ReadyEcdsaSignerSession,
  ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ReadyEcdsaMaterial } from './ecdsaMaterialState';
import type { EcdsaSelectionDiagnostics } from './ecdsaSelection';
import type {
  EvmFamilyThresholdEcdsaEmailOtpSigning,
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaPasskeyReconnect,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import type {
  EvmFamilyThresholdEcdsaStepUp,
  EvmFamilyThresholdEcdsaStepUpRuntime,
  EvmFamilyThresholdReconnectRuntime,
} from './requireEvmFamilyStepUpAuth';
import type { SigningAuthPlan } from '../../stepUpConfirmation/types';

declare const readyMaterial: ReadyEvmFamilyEcdsaMaterial;
declare const readyToSignMaterial: ReadyEcdsaMaterial;
declare const signerSession: ReadyEcdsaSignerSession;
declare const operation: EvmFamilyThresholdEcdsaOperation;
declare const signingAuthPlan: SigningAuthPlan;
declare const stepUpRuntime: EvmFamilyThresholdEcdsaStepUpRuntime;
declare const diagnostics: EcdsaSelectionDiagnostics;

void ({
  readyToSignMaterial,
  readyMaterial,
  signerSession,
  operation,
} satisfies EvmFamilyThresholdEcdsaReauthResult);

void ({
  readyToSignMaterial,
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

const diagnosticsAsReauthMaterial = {
  readyToSignMaterial: diagnostics,
  readyMaterial,
  signerSession,
  operation,
};

// @ts-expect-error admission results do not accept diagnostics as signer material.
void (diagnosticsAsReauthMaterial satisfies EvmFamilyThresholdEcdsaReauthResult);

const missingSignerSession = {
  readyMaterial,
  operation,
};

// @ts-expect-error reauth results must carry ready signer-session material
void (missingSignerSession satisfies EvmFamilyThresholdEcdsaReauthResult);

void ({
  complete: async () => ({ readyToSignMaterial, readyMaterial, signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaEmailOtpSigning);

void ({
  // @ts-expect-error Email OTP reauth completion must return ready material
  complete: async () => ({ signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaEmailOtpSigning);

void ({
  reconnect: async () => ({ readyToSignMaterial, readyMaterial, signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaPasskeyReconnect);

void ({
  // @ts-expect-error passkey reconnect must return ready material
  reconnect: async () => ({ signerSession, operation }),
} satisfies EvmFamilyThresholdEcdsaPasskeyReconnect);

void ({
  ensureThresholdEcdsaReadyMaterial: async () => ({
    readyToSignMaterial,
    readyMaterial,
    signerSession,
    operation,
  }),
} satisfies EvmFamilyThresholdReconnectRuntime);

void ({
  // @ts-expect-error threshold reconnect must return ready material
  ensureThresholdEcdsaReadyMaterial: async () => ({ signerSession, operation }),
} satisfies EvmFamilyThresholdReconnectRuntime);

void ({
  kind: 'required_admitted',
  authPlan: {
    kind: 'planned',
    signingAuthPlan,
  },
  operation,
  signerSession,
  singleUseEmailOtpSession: false,
  runtime: stepUpRuntime,
} satisfies EvmFamilyThresholdEcdsaStepUp);

const admittedWithoutSignerSession = {
  kind: 'required_admitted',
  authPlan: {
    kind: 'planned',
    signingAuthPlan,
  },
  operation,
  singleUseEmailOtpSession: false,
  runtime: stepUpRuntime,
};

// @ts-expect-error admitted threshold ECDSA step-up state requires ready signer material
void (admittedWithoutSignerSession satisfies EvmFamilyThresholdEcdsaStepUp);

export {};
