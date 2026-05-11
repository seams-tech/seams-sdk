export const refactor36TransitionalLifecycleOptionals = [] as const;

export const refactor36RawIdentityParseAllowlist = [] as const;

export const refactor36EcdsaActivationConstructionAllowlist = [
  {
    file: 'client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts',
    ownerPhase: '12',
    reason: 'Provisioner owns strict ECDSA activation branch builders from provision plans.',
  },
  {
    file: 'client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
    ownerPhase: '12',
    reason: 'Provision handoff owns strict ECDSA activation request normalization into bootstrap args.',
  },
] as const;
