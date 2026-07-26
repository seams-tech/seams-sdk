import type {
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  RouterAbEd25519YaoCapabilityReplacementOperationV1,
  RouterAbEd25519YaoActiveCapabilityLookupV1,
  RouterAbEd25519YaoRecoveryActivationClaimV1,
  RouterAbEd25519YaoRecoveryActivationCommitInputV1,
} from './routerAbEd25519YaoRecovery';

type AssertNever<T extends never> = T;

type ActivationUncertaintyCannotCrossCommitBoundary = AssertNever<
  Extract<
    RouterAbEd25519YaoRecoveryActivationCommitInputV1['outcome'],
    { readonly kind: 'backend_uncertain' }
  >
>;

const replacementOperation: RouterAbEd25519YaoCapabilityReplacementOperationV1 = {
  kind: 'router_ab_ed25519_yao_capability_replacement_operation_v1',
  operationId: 'recovery-lifecycle-1',
  operationFingerprint: 'activation-fingerprint-1',
};

const activationClaim: RouterAbEd25519YaoRecoveryActivationClaimV1 = {
  kind: 'router_ab_ed25519_yao_recovery_activation_claim_v1',
  lifecycleId: replacementOperation.operationId,
  recoveryKey: 'recovery-key-1',
  sessionId: 'session-1',
  activationFingerprint: replacementOperation.operationFingerprint,
  disposition: 'initial',
};

const activeCapabilityLookup: RouterAbEd25519YaoActiveCapabilityLookupV1 = {
  kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
  walletId: 'wallet-1',
  nearEd25519SigningKeyId: 'ed25519ks_1',
  signerSlot: 1,
  signingWorkerId: 'signing-worker-1',
  participantIds: [1, 2],
};

const lookupWithChainProjection: RouterAbEd25519YaoActiveCapabilityLookupV1 = {
  kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
  walletId: 'wallet-1',
  // @ts-expect-error capability selection excludes the mutable NEAR account projection
  nearAccountId: 'wallet-1.testnet',
  nearEd25519SigningKeyId: 'ed25519ks_1',
  signerSlot: 1,
  signingWorkerId: 'signing-worker-1',
  participantIds: [1, 2],
};

// @ts-expect-error activation claims always state whether work is initial or reconciliation
const claimWithoutDisposition: RouterAbEd25519YaoRecoveryActivationClaimV1 = {
  kind: 'router_ab_ed25519_yao_recovery_activation_claim_v1',
  lifecycleId: activationClaim.lifecycleId,
  recoveryKey: activationClaim.recoveryKey,
  sessionId: activationClaim.sessionId,
  activationFingerprint: activationClaim.activationFingerprint,
};

// @ts-expect-error successful persistence must distinguish a write from receipt redelivery
const successWithoutDisposition: RouterAbEd25519YaoCapabilityPersistenceResultV1 = {
  ok: true,
};

// @ts-expect-error uncertain persistence cannot be represented as an ordinary rejection
const uncertainWithoutDisposition: RouterAbEd25519YaoCapabilityPersistenceResultV1 = {
  ok: false,
  code: 'capability_persistence_uncertain',
  message: 'response lost',
};

void claimWithoutDisposition;
void activeCapabilityLookup;
void lookupWithChainProjection;
void successWithoutDisposition;
void uncertainWithoutDisposition;
