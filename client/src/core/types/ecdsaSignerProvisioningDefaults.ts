export interface EcdsaSignerProvisioningSession {
  kind: 'jwt' | 'cookie';
  ttlMs: number;
  remainingUses: number;
}

export interface EcdsaSignerProvisioningPolicy {
  enabled: boolean;
  signingSession: EcdsaSignerProvisioningSession;
}

export interface EcdsaSignerProvisioningDefaults {
  tempo: EcdsaSignerProvisioningPolicy;
  evm: EcdsaSignerProvisioningPolicy;
}
