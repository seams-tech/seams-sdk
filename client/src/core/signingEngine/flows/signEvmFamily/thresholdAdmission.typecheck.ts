import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ReadyEvmFamilyEcdsaMaterial } from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  EvmFamilyThresholdEcdsaEmailOtpSigning,
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaPasskeyReconnect,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import type { EvmFamilyThresholdReconnectRuntime } from './requireEvmFamilyStepUpAuth';

declare const readyMaterial: ReadyEvmFamilyEcdsaMaterial;
declare const keyRef: ThresholdEcdsaSecp256k1KeyRef;
declare const operation: EvmFamilyThresholdEcdsaOperation;

void ({
  readyMaterial,
  keyRef,
  operation,
} satisfies EvmFamilyThresholdEcdsaReauthResult);

const missingReadyMaterial = {
  keyRef,
  operation,
};

// @ts-expect-error reauth results must carry canonical ready EVM-family material
void (missingReadyMaterial satisfies EvmFamilyThresholdEcdsaReauthResult);

void ({
  complete: async () => ({ readyMaterial, keyRef, operation }),
} satisfies EvmFamilyThresholdEcdsaEmailOtpSigning);

void ({
  // @ts-expect-error Email OTP reauth completion must return ready material
  complete: async () => ({ keyRef, operation }),
} satisfies EvmFamilyThresholdEcdsaEmailOtpSigning);

void ({
  reconnect: async () => ({ readyMaterial, keyRef, operation }),
} satisfies EvmFamilyThresholdEcdsaPasskeyReconnect);

void ({
  // @ts-expect-error passkey reconnect must return ready material
  reconnect: async () => ({ keyRef, operation }),
} satisfies EvmFamilyThresholdEcdsaPasskeyReconnect);

void ({
  ensureThresholdEcdsaKeyRefReady: async () => ({ readyMaterial, keyRef, operation }),
} satisfies EvmFamilyThresholdReconnectRuntime);

void ({
  // @ts-expect-error threshold reconnect must return ready material
  ensureThresholdEcdsaKeyRefReady: async () => ({ keyRef, operation }),
} satisfies EvmFamilyThresholdReconnectRuntime);

export {};
