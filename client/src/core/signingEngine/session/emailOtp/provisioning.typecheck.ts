import type {
  EmailOtpEd25519SessionReconstructionPlan,
  ReconstructEmailOtpEd25519SessionArgs,
  RegisterEmailOtpEd25519CapabilityArgs,
} from './provisioning';

const commonRegistration = {
  nearAccountId: 'alice.testnet',
  relayUrl: 'https://relay.example',
  rpId: 'localhost',
  prfFirstB64u: 'prf-first-b64u',
  emailOtpAuthContext: {
    policy: 'session',
    retention: 'session',
    reason: 'login',
    authMethod: 'email_otp',
  },
  registrationAttemptId: 'registration-attempt',
} satisfies Omit<
  RegisterEmailOtpEd25519CapabilityArgs,
  'kind' | 'walletSigningSessionId' | 'ecdsaThresholdSessionId'
>;

const validRegistration = {
  ...commonRegistration,
  kind: 'registration_ed25519_provisioning',
} satisfies RegisterEmailOtpEd25519CapabilityArgs;

const validRegistrationCompanion = {
  ...commonRegistration,
  kind: 'registration_ed25519_companion_provisioning',
  walletSigningSessionId: 'wallet-signing-session',
  ecdsaThresholdSessionId: 'ecdsa-threshold-session',
} satisfies RegisterEmailOtpEd25519CapabilityArgs;

void validRegistration;
void validRegistrationCompanion;

// @ts-expect-error registration provisioning requires a registration attempt
const invalidRegistrationWithoutAttempt: RegisterEmailOtpEd25519CapabilityArgs = {
  nearAccountId: 'alice.testnet',
  relayUrl: 'https://relay.example',
  rpId: 'localhost',
  prfFirstB64u: 'prf-first-b64u',
  emailOtpAuthContext: commonRegistration.emailOtpAuthContext,
  kind: 'registration_ed25519_provisioning',
};

// @ts-expect-error registration provisioning cannot carry companion ECDSA identity
const invalidRegistrationWithCompanionIds: RegisterEmailOtpEd25519CapabilityArgs = {
  ...commonRegistration,
  kind: 'registration_ed25519_provisioning',
  walletSigningSessionId: 'wallet-signing-session',
  ecdsaThresholdSessionId: 'ecdsa-threshold-session',
};

// @ts-expect-error companion registration requires wallet signing-session identity
const invalidCompanionWithoutWalletId: RegisterEmailOtpEd25519CapabilityArgs = {
  ...commonRegistration,
  kind: 'registration_ed25519_companion_provisioning',
  ecdsaThresholdSessionId: 'ecdsa-threshold-session',
};

// @ts-expect-error companion registration requires ECDSA threshold-session identity
const invalidCompanionWithoutThresholdSessionId: RegisterEmailOtpEd25519CapabilityArgs = {
  ...commonRegistration,
  kind: 'registration_ed25519_companion_provisioning',
  walletSigningSessionId: 'wallet-signing-session',
};

const validReconstruction = {
  kind: 'session_ed25519_reconstruction',
  nearAccountId: 'alice.testnet',
  relayUrl: 'https://relay.example',
  rpId: 'localhost',
  prfFirstB64u: 'prf-first-b64u',
  emailOtpAuthContext: commonRegistration.emailOtpAuthContext,
  routeAuth: {
    kind: 'threshold_session',
    jwt: 'threshold-session.jwt.sig',
  },
  runtimePolicyScope: {
    orgId: 'org',
    projectId: 'project',
    envId: 'dev',
    signingRootVersion: 'root',
  },
  walletSigningSessionId: 'wallet-signing-session',
  ecdsaThresholdSessionId: 'ecdsa-threshold-session',
  ed25519Key: {
    relayerKeyId: 'ed25519:relayer',
    keyVersion: 'threshold-ed25519-hss-v1',
    participantIds: [1, 2],
  },
} satisfies ReconstructEmailOtpEd25519SessionArgs;

void validReconstruction;

const validReconstructionPlan = {
  kind: 'reconstruct',
  ed25519Key: validReconstruction.ed25519Key,
  runtimePolicyScope: validReconstruction.runtimePolicyScope,
} satisfies EmailOtpEd25519SessionReconstructionPlan;

const validDeferredReconstructionPlan = {
  kind: 'defer',
  reason: 'missing_runtime_policy_scope',
} satisfies EmailOtpEd25519SessionReconstructionPlan;

const invalidReconstructionPlanWithoutRuntimeScope: EmailOtpEd25519SessionReconstructionPlan = {
  kind: 'reconstruct',
  ed25519Key: validReconstruction.ed25519Key,
  // @ts-expect-error reconstruction plans require runtime policy scope
  runtimePolicyScope: undefined,
};

const invalidReconstructionWithRegistrationAttempt: ReconstructEmailOtpEd25519SessionArgs = {
  ...validReconstruction,
  // @ts-expect-error session reconstruction cannot spend registration attempts
  registrationAttemptId: 'registration-attempt',
};

const invalidReconstructionWithoutRouteAuth: ReconstructEmailOtpEd25519SessionArgs = {
  ...validReconstruction,
  // @ts-expect-error session reconstruction requires route auth
  routeAuth: undefined,
};

const invalidReconstructionWithoutRuntimeScope: ReconstructEmailOtpEd25519SessionArgs = {
  ...validReconstruction,
  // @ts-expect-error session reconstruction requires runtime policy scope
  runtimePolicyScope: undefined,
};

const invalidReconstructionWithoutKey: ReconstructEmailOtpEd25519SessionArgs = {
  ...validReconstruction,
  // @ts-expect-error session reconstruction requires concrete Ed25519 key identity
  ed25519Key: undefined,
};

void invalidRegistrationWithoutAttempt;
void invalidRegistrationWithCompanionIds;
void invalidCompanionWithoutWalletId;
void invalidCompanionWithoutThresholdSessionId;
void invalidReconstructionWithRegistrationAttempt;
void invalidReconstructionWithoutRouteAuth;
void invalidReconstructionWithoutRuntimeScope;
void invalidReconstructionWithoutKey;
void validReconstructionPlan;
void validDeferredReconstructionPlan;
void invalidReconstructionPlanWithoutRuntimeScope;
