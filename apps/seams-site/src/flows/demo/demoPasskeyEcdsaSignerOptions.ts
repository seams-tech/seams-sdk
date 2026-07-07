export type DemoEcdsaSignerProvisioningSession = {
  kind: 'jwt' | 'cookie';
  ttlMs: number;
  remainingUses: number;
};

export type DemoEcdsaSignerProvisioningPolicy = {
  enabled: boolean;
  signingSession: DemoEcdsaSignerProvisioningSession;
};

export type DemoEcdsaSignerProvisioningDefaults = {
  tempo: DemoEcdsaSignerProvisioningPolicy;
  evm: DemoEcdsaSignerProvisioningPolicy;
};

export function demoPasskeyEcdsaSignerOptions(
  defaults: DemoEcdsaSignerProvisioningDefaults,
): DemoEcdsaSignerProvisioningDefaults {
  return {
    tempo: {
      ...defaults.tempo,
      enabled: true,
    },
    evm: {
      ...defaults.evm,
      enabled: true,
    },
  };
}
