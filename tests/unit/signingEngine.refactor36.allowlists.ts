type Refactor36GuardAllowlistEntry = {
  file: string;
  ownerPhase: string;
  reason: string;
};

export const refactor36TransitionalLifecycleOptionals: readonly Refactor36GuardAllowlistEntry[] = [];

export const refactor36RawIdentityParseAllowlist: readonly Refactor36GuardAllowlistEntry[] = [];

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

export const reduceNearAccountIdAccountToSubjectAllowlist = [
  { file: 'client/src/core/signingEngine/flows/recovery/exportLaneSelection.ts', occurrences: 1 },
  { file: 'client/src/core/signingEngine/flows/signNear/signNear.ts', occurrences: 1 },
] as const;

export const reduceNearAccountIdForbiddenPathNearOwnedAllowlist = [
  {
    file: 'client/src/core/signingEngine/session/warmCapabilities/public.ts',
    occurrences: 6,
    ownerPhase: '8',
    reason: 'Ed25519 warm-session helpers remain NEAR-account-scoped in a mixed directory.',
  },
  {
    file: 'client/src/core/signingEngine/session/warmCapabilities/persistence.ts',
    occurrences: 4,
    ownerPhase: '8',
    reason: 'Warm Ed25519 persistence remains NEAR-account-scoped in a mixed directory.',
  },
  {
    file: 'client/src/core/signingEngine/session/warmCapabilities/persistence.typecheck.ts',
    occurrences: 1,
    ownerPhase: '8',
    reason: 'Warm Ed25519 persistence type fixture remains NEAR-account-scoped.',
  },
  {
    file: 'client/src/core/signingEngine/session/warmCapabilities/statusReader.ts',
    occurrences: 10,
    ownerPhase: '8',
    reason: 'Warm Ed25519 status readers remain NEAR-account-scoped in a mixed directory.',
  },
  {
    file: 'client/src/core/signingEngine/session/warmCapabilities/types.ts',
    occurrences: 4,
    ownerPhase: '8',
    reason: 'Warm Ed25519 public status types remain NEAR-account-scoped in a mixed directory.',
  },
  {
    file: 'client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
    occurrences: 20,
    ownerPhase: '8',
    reason: 'Mixed passkey worker still owns NEAR export/account confirmation branches.',
  },
  {
    file: 'wasm/hss_client_signer/src/client_inputs.rs',
    occurrences: 2,
    ownerPhase: '8',
    reason: 'Ed25519 HSS client-input derivation remains account-scoped.',
  },
  {
    file: 'wasm/hss_client_signer/src/threshold_hss.rs',
    occurrences: 2,
    ownerPhase: '8',
    reason: 'Ed25519 HSS canonical context remains account-scoped.',
  },
] as const;

export const reduceNearAccountIdForbiddenPathTemporaryResidueAllowlist = [] as const;
