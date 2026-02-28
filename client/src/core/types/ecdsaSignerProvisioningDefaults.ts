export interface EcdsaSignerProvisioningSession {
  kind: 'jwt' | 'cookie';
  ttlMs: number;
  remainingUses: number;
}

export interface EcdsaSignerProvisioningPolicy {
  enabled: boolean;
  participantIds: readonly number[];
  signingSession: EcdsaSignerProvisioningSession;
  smartAccount?: {
    chainId: number;
    factory?: string;
    entryPoint?: string;
    salt?: string;
    counterfactualAddress?: string;
  };
}

export interface EcdsaSignerProvisioningDefaults {
  tempo: EcdsaSignerProvisioningPolicy;
  evm: EcdsaSignerProvisioningPolicy;
}
