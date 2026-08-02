import {
  AUTH_FACTOR_KINDS,
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  GRANT_EVIDENCE_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  VAULT_OPERATION_KINDS,
  buildEvmEcdsaMpcOperationRef,
  buildGrantEvidenceRequirement,
  buildNearEd25519MpcOperationRef,
  buildVaultOperationRef,
  type AuthFactorId,
  type CapabilityOperationRef,
  type GrantEvidenceKind,
  type GrantEvidenceRequirement,
  type AuthorizationGrantRef,
  type WalletSessionAuthorizationId,
  type AuthorizedOperationId,
  type SeamsSessionId,
} from './capabilityKinds';

const vaultOperation = buildVaultOperationRef(VAULT_OPERATION_KINDS.proxyUse);
const nearOperation = buildNearEd25519MpcOperationRef(
  NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
);
const evmOperation = buildEvmEcdsaMpcOperationRef(EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction);

const operationRefs: readonly CapabilityOperationRef[] = [
  vaultOperation,
  nearOperation,
  evmOperation,
];
void operationRefs;

buildGrantEvidenceRequirement({
  mode: 'any',
  evidenceKinds: [GRANT_EVIDENCE_KINDS.passkeyAssertion, GRANT_EVIDENCE_KINDS.emailOtp],
});

const canonicalRequirement: GrantEvidenceRequirement = {
  mode: 'all',
  evidenceKinds: [GRANT_EVIDENCE_KINDS.seamsSession],
};
void canonicalRequirement;

const authFactorKinds = [AUTH_FACTOR_KINDS.passkey, AUTH_FACTOR_KINDS.emailOtp] as const;
void authFactorKinds;

// @ts-expect-error A vault capability cannot carry a NEAR operation.
const invalidVaultOperation: CapabilityOperationRef = {
  capabilityKind: CAPABILITY_KINDS.vaultAccess,
  operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
};
void invalidVaultOperation;

// @ts-expect-error An EVM capability cannot carry a vault operation.
const invalidEvmOperation: CapabilityOperationRef = {
  capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
  operationKind: VAULT_OPERATION_KINDS.reveal,
};
void invalidEvmOperation;

// @ts-expect-error Evidence requirements must be nonempty.
buildGrantEvidenceRequirement({ mode: 'all', evidenceKinds: [] });

// @ts-expect-error mpc_signer_proof is follow-on work and is outside the closed union.
const unsupportedEvidence: GrantEvidenceKind = 'mpc_signer_proof';
void unsupportedEvidence;

declare const seamsSessionId: SeamsSessionId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const authorizedOperationId: AuthorizedOperationId;
const authorizationRef: AuthorizationGrantRef = {
  kind: 'wallet_session_authorization',
  authorizationId,
};
void authorizationRef;
// @ts-expect-error Session identity cannot substitute for reusable authorization identity.
const invalidAuthorizationId: WalletSessionAuthorizationId = seamsSessionId;
void invalidAuthorizationId;
// @ts-expect-error Wallet authorization identity cannot substitute for operation identity.
const invalidOperationId: AuthorizedOperationId = authorizationId;
void invalidOperationId;

declare const factorId: AuthFactorId;
// @ts-expect-error Factor and session identities are independent.
const invalidSessionId: SeamsSessionId = factorId;
void invalidSessionId;
