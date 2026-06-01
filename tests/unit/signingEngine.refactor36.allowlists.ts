type Refactor36GuardAllowlistEntry = {
  file: string;
  ownerPhase: string;
  reason: string;
};

type Refactor36PathOccurrenceAllowlistEntry = {
  file: string;
  occurrences: number;
  ownerPhase: string;
  reason: string;
};

export const refactor36EcdsaActivationConstructionAllowlist = [
  {
    file: 'client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
    ownerPhase: '12',
    reason: 'Provision handoff owns strict ECDSA activation request normalization into bootstrap args.',
  },
  {
    file: 'client/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
    ownerPhase: '5',
    reason: 'Provision use case owns strict ECDSA activation branch builders from provision plans.',
  },
] as const;

export const reduceNearAccountIdAccountToSubjectAllowlist: readonly Refactor36PathOccurrenceAllowlistEntry[] =
  [
    {
      file: 'client/src/core/SeamsPasskey/index.ts',
      occurrences: 1,
      ownerPhase: '8',
      reason: 'Email OTP registration bridge still projects the selected NEAR account into wallet id.',
    },
    {
      file: 'client/src/core/SeamsPasskey/login.ts',
      occurrences: 8,
      ownerPhase: '8',
      reason: 'Login restore and repair bridges derive wallet-scoped ECDSA reads from the selected NEAR account.',
    },
    {
      file: 'client/src/core/signingEngine/flows/registration/accountLifecycle.ts',
      occurrences: 1,
      ownerPhase: '8',
      reason: 'Registration account projection still initializes the current wallet preference from the NEAR account.',
    },
    {
      file: 'client/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts',
      occurrences: 1,
      ownerPhase: '8',
      reason: 'Mixed Email OTP warm-up still derives wallet id for the ECDSA portion from the NEAR account.',
    },
  ];

export const reduceNearAccountIdForbiddenPathNearOwnedAllowlist = [
  {
    file: 'client/src/core/signingEngine/session/warmCapabilities/public.ts',
    occurrences: 4,
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
    file: 'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    occurrences: 11,
    ownerPhase: '8',
    reason: 'Mixed Email OTP worker still owns NEAR Ed25519 account branches.',
  },
  {
    file: 'client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
    occurrences: 20,
    ownerPhase: '8',
    reason: 'Mixed passkey worker still owns NEAR export/account confirmation branches.',
  },
  {
    file: 'client/src/core/signingEngine/workerManager/workerTypes.ts',
    occurrences: 1,
    ownerPhase: '8',
    reason: 'Worker type registry still carries the NEAR account request kind for Ed25519 operations.',
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
