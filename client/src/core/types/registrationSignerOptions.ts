export interface RegistrationThresholdEcdsaSignerOptions {
  enabled: boolean;
  participantIds: readonly number[];
  sessionKind: 'jwt' | 'cookie';
  ttlMs: number;
  remainingUses: number;
  smartAccount?: {
    chainId?: string;
    factory?: string;
    entryPoint?: string;
    salt?: string;
    counterfactualAddress?: string;
  };
}

export interface RegistrationSignerOptions {
  tempo: RegistrationThresholdEcdsaSignerOptions;
  evm: RegistrationThresholdEcdsaSignerOptions;
}
