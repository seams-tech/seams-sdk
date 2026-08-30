import {
  AUTH_FACTOR_KINDS,
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  AUTHORIZATION_EVIDENCE_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  VAULT_OPERATION_KINDS,
  WALLET_SESSION_CLIENT_CAPABILITY_V1,
  buildEvmEcdsaMpcOperationRef,
  buildAuthorizationEvidenceRequirement,
  buildNearEd25519MpcOperationRef,
  buildVaultOperationRef,
  type AuthFactorId,
  type CapabilityOperationRef,
  type AuthorizationEvidenceKind,
  type AuthorizationEvidenceRequirement,
  type AuthorizationGrantRef,
  type WalletSessionAuthorizationId,
  type WalletSessionClientCapabilityV1,
  type AuthorizedOperationId,
  type EcdsaAuthorizationSessionId,
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

buildAuthorizationEvidenceRequirement({
  mode: 'any',
  evidenceKinds: [
    AUTHORIZATION_EVIDENCE_KINDS.passkeyAssertion,
    AUTHORIZATION_EVIDENCE_KINDS.emailOtp,
  ],
});

const canonicalRequirement: AuthorizationEvidenceRequirement = {
  mode: 'all',
  evidenceKinds: [AUTHORIZATION_EVIDENCE_KINDS.seamsSession],
};
void canonicalRequirement;

const authFactorKinds = [AUTH_FACTOR_KINDS.passkey, AUTH_FACTOR_KINDS.emailOtp] as const;
void authFactorKinds;

const walletSessionClientCapability: WalletSessionClientCapabilityV1 =
  WALLET_SESSION_CLIENT_CAPABILITY_V1;
void walletSessionClientCapability;

// @ts-expect-error The client capability is a closed, exact literal.
const unsupportedWalletSessionClientCapability: WalletSessionClientCapabilityV1 =
  'direct_exact_response_future_record_tolerant_v2';
void unsupportedWalletSessionClientCapability;

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
buildAuthorizationEvidenceRequirement({ mode: 'all', evidenceKinds: [] });

// @ts-expect-error mpc_signer_proof is follow-on work and is outside the closed union.
const unsupportedEvidence: AuthorizationEvidenceKind = 'mpc_signer_proof';
void unsupportedEvidence;

declare const ecdsaAuthorizationSessionId: EcdsaAuthorizationSessionId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const authorizedOperationId: AuthorizedOperationId;
const authorizationRef: AuthorizationGrantRef = {
  kind: 'wallet_session_authorization',
  authorizationId,
};
void authorizationRef;
// @ts-expect-error Session identity cannot substitute for reusable authorization identity.
const invalidAuthorizationId: WalletSessionAuthorizationId = ecdsaAuthorizationSessionId;
void invalidAuthorizationId;
// @ts-expect-error Wallet authorization identity cannot substitute for operation identity.
const invalidOperationId: AuthorizedOperationId = authorizationId;
void invalidOperationId;

declare const factorId: AuthFactorId;
// @ts-expect-error Factor and session identities are independent.
const invalidSessionId: EcdsaAuthorizationSessionId = factorId;
void invalidSessionId;
