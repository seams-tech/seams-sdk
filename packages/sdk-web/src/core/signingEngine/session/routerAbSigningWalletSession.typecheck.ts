import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import { buildRouterAbEd25519SigningMaterialRef } from '../threshold/ed25519/workerMaterialBinding';
import { buildRouterAbEcdsaHssSigningMaterialRef } from '../routerAb/ecdsaHss/signingMaterialRef';
import type {
  RouterAbEcdsaHssSigningWalletSession,
  RouterAbEd25519PersistedSigningRecordState,
  RouterAbEd25519SigningWalletSession,
  RouterAbSigningWalletSessionAuth,
} from './routerAbSigningWalletSession';
import type { ThresholdEd25519SessionRecord } from './persistence/records';
import { toWalletId } from '../interfaces/ecdsaChainTarget';
import { ed25519KeyScopeIdFromString } from '@shared/utils/registrationIntent';

type ExactType<TValue, TShape> = TValue extends TShape
  ? Exclude<keyof TValue, keyof TShape> extends never
    ? TValue
    : never
  : never;

type RouterAbEd25519RuntimeValidatedPersistedState = Extract<
  RouterAbEd25519PersistedSigningRecordState,
  { kind: 'runtime_validated' }
>;

function exactEd25519RuntimeValidatedState<TValue extends RouterAbEd25519RuntimeValidatedPersistedState>(
  value: ExactType<TValue, RouterAbEd25519RuntimeValidatedPersistedState>,
): TValue {
  return value;
}

const walletSessionAuth = {
  kind: 'wallet_session_jwt',
  walletSessionJwt: 'wallet-session-jwt',
  credential: {
    kind: 'jwt',
    walletSessionJwt: 'wallet-session-jwt',
  },
} satisfies RouterAbSigningWalletSessionAuth;
void walletSessionAuth;

const runtimePolicyScope = {
  orgId: 'org-test',
  projectId: 'project-test',
  envId: 'dev',
  signingRootVersion: 'default',
} satisfies ThresholdRuntimePolicyScope;
void runtimePolicyScope;

const ed25519RouterAbNormalSigning = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'signing-worker-a',
} satisfies RouterAbEd25519NormalSigningState;
void ed25519RouterAbNormalSigning;

const ed25519SigningMaterial = buildRouterAbEd25519SigningMaterialRef({
  materialHandle: 'ed25519-worker-material:threshold-session-1:binding',
  bindingDigest: 'binding-digest',
  clientVerifyingShareB64u: 'client-verifying-share',
});
void ed25519SigningMaterial;

const ecdsaRouterAbNormalSigning = {
  kind: 'router_ab_ecdsa_hss_normal_signing_v1',
  scope: {
    wallet_key_id: 'localhost',
    wallet_id: 'alice.testnet',
    ecdsa_threshold_key_id: 'ehss-shared-key',
    signing_root_id: 'project-test:dev',
    signing_root_version: 'default',
    context: {
      application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    },
    public_identity: {
      context_binding_b64u: 'context-binding',
      client_public_key33_b64u: 'client-public-key',
      server_public_key33_b64u: 'server-public-key',
      threshold_public_key33_b64u: 'threshold-public-key',
      ethereum_address20_b64u: 'ethereum-address',
      client_share_retry_counter: 0,
      server_share_retry_counter: 0,
    },
    signing_worker: {
      server_id: 'signing-worker-a',
      key_epoch: 'epoch-1',
      recipient_encryption_key: 'x25519:recipient',
    },
    activation_epoch: 'activation-epoch-1',
  },
} satisfies RouterAbEcdsaHssNormalSigningStateV1;
void ecdsaRouterAbNormalSigning;

const ecdsaSigningMaterial = buildRouterAbEcdsaHssSigningMaterialRef({
  routerAbState: ecdsaRouterAbNormalSigning,
});
void ecdsaSigningMaterial;

const validEd25519SigningWalletSession = {
  curve: 'ed25519',
  auth: walletSessionAuth,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
  signingMaterial: ed25519SigningMaterial,
  runtimePolicyScope,
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  routerAbNormalSigning: ed25519RouterAbNormalSigning,
} satisfies RouterAbEd25519SigningWalletSession;
void validEd25519SigningWalletSession;

const validEcdsaSigningWalletSession = {
  curve: 'ecdsa',
  auth: walletSessionAuth,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  remainingUses: 1,
  expiresAtMs: 1_900_000_000_000,
  signingMaterial: ecdsaSigningMaterial,
  runtimePolicyScope,
  routerAbEcdsaHssNormalSigning: ecdsaRouterAbNormalSigning,
} satisfies RouterAbEcdsaHssSigningWalletSession;
void validEcdsaSigningWalletSession;

const ed25519MissingSigningMaterial = {
  ...validEd25519SigningWalletSession,
  // @ts-expect-error Signable Ed25519 Wallet Session state requires a parsed material ref.
  signingMaterial: undefined,
} satisfies RouterAbEd25519SigningWalletSession;
void ed25519MissingSigningMaterial;

const ed25519MissingBindingDigest = {
  ...validEd25519SigningWalletSession,
  signingMaterial: {
    ...ed25519SigningMaterial,
    // @ts-expect-error Signable Ed25519 Wallet Session material ref requires a material binding digest.
    bindingDigest: undefined,
  },
} satisfies RouterAbEd25519SigningWalletSession;
void ed25519MissingBindingDigest;

const ed25519MissingMaterialHandle = {
  ...validEd25519SigningWalletSession,
  signingMaterial: {
    ...ed25519SigningMaterial,
    // @ts-expect-error Signable Ed25519 Wallet Session material ref requires a worker material handle.
    materialHandle: undefined,
  },
} satisfies RouterAbEd25519SigningWalletSession;
void ed25519MissingMaterialHandle;

const ed25519MissingSigningGrant = {
  ...validEd25519SigningWalletSession,
  // @ts-expect-error Signable Ed25519 Wallet Session state requires the signing grant id.
  signingGrantId: undefined,
} satisfies RouterAbEd25519SigningWalletSession;
void ed25519MissingSigningGrant;

const ed25519MissingSigningRootId = {
  ...validEd25519SigningWalletSession,
  // @ts-expect-error Signable Ed25519 Wallet Session state requires signing root id.
  signingRootId: undefined,
} satisfies RouterAbEd25519SigningWalletSession;
void ed25519MissingSigningRootId;

const ed25519MissingSigningRootVersion = {
  ...validEd25519SigningWalletSession,
  // @ts-expect-error Signable Ed25519 Wallet Session state requires signing root version.
  signingRootVersion: undefined,
} satisfies RouterAbEd25519SigningWalletSession;
void ed25519MissingSigningRootVersion;

const ed25519RawClientBase = {
  ...validEd25519SigningWalletSession,
  // @ts-expect-error Signable Ed25519 Wallet Session state must not carry raw client base material.
  xClientBaseB64u: 'raw-client-base',
} satisfies RouterAbEd25519SigningWalletSession;
void ed25519RawClientBase;

const validEd25519SessionRecord = {
  walletId: toWalletId('alice-wallet'),
  nearAccountId: 'alice.testnet',
  ed25519KeyScopeId: ed25519KeyScopeIdFromString('alice-wallet'),
  rpId: 'localhost',
  relayerUrl: 'https://relay.example',
  relayerKeyId: 'ed25519:relayer',
  participantIds: [1, 2],
  signingRootId: 'project-test:dev',
  signingRootVersion: 'default',
  runtimePolicyScope,
  clientVerifyingShareB64u: 'client-verifying-share',
  ed25519WorkerMaterialHandle: 'ed25519-worker-material:threshold-session-1:binding',
  ed25519WorkerMaterialBindingDigest: 'binding-digest',
  routerAbNormalSigning: ed25519RouterAbNormalSigning,
  thresholdSessionKind: 'jwt',
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  walletSessionJwt: 'wallet-session-jwt',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 1,
  updatedAtMs: 1_800_000_000_000,
  source: 'registration',
} satisfies ThresholdEd25519SessionRecord;
void validEd25519SessionRecord;

const validEd25519RuntimeValidatedState = {
  kind: 'runtime_validated',
  record: validEd25519SessionRecord,
  value: validEd25519SigningWalletSession,
} satisfies RouterAbEd25519PersistedSigningRecordState;
void validEd25519RuntimeValidatedState;
exactEd25519RuntimeValidatedState(validEd25519RuntimeValidatedState);

const ed25519RuntimeValidatedSpreadExtra = {
  ...validEd25519RuntimeValidatedState,
  xClientBaseB64u: 'raw-client-base',
};
exactEd25519RuntimeValidatedState(
  // @ts-expect-error Runtime-validated Ed25519 persisted state rejects broad-spread extras.
  ed25519RuntimeValidatedSpreadExtra,
);

const ed25519RuntimeValidatedMissingValue = {
  kind: 'runtime_validated',
  record: validEd25519SessionRecord,
  value: undefined,
  // @ts-expect-error Runtime-validated Ed25519 persisted state requires parsed signing value.
} satisfies RouterAbEd25519PersistedSigningRecordState;
void ed25519RuntimeValidatedMissingValue;

const ed25519RuntimeValidatedWithReason = {
  kind: 'runtime_validated',
  record: validEd25519SessionRecord,
  value: validEd25519SigningWalletSession,
  // @ts-expect-error Runtime-validated Ed25519 persisted state cannot carry failure reasons.
  reason: 'worker_material_unvalidated',
} satisfies RouterAbEd25519PersistedSigningRecordState;
void ed25519RuntimeValidatedWithReason;

const ed25519RestoreAvailableWithValue = {
  kind: 'restore_available',
  record: validEd25519SessionRecord,
  reason: 'loaded_material_missing',
  value: validEd25519SigningWalletSession,
  // @ts-expect-error Restore-available Ed25519 persisted state cannot be signable.
} satisfies RouterAbEd25519PersistedSigningRecordState;
void ed25519RestoreAvailableWithValue;

const ed25519MaterialHintWithSealedMaterial = {
  kind: 'material_hint_unvalidated',
  record: validEd25519SessionRecord,
  reason: 'worker_material_unvalidated',
  // @ts-expect-error Material-hint Ed25519 persisted state does not carry sealed restore material.
  sealedMaterial: 'sealed-worker-material',
} satisfies RouterAbEd25519PersistedSigningRecordState;
void ed25519MaterialHintWithSealedMaterial;

const ed25519PendingWithValue = {
  kind: 'auth_ready_material_pending',
  record: validEd25519SessionRecord,
  reason: 'missing_material_handle',
  value: validEd25519SigningWalletSession,
  // @ts-expect-error Pending Ed25519 persisted state cannot be signable.
} satisfies RouterAbEd25519PersistedSigningRecordState;
void ed25519PendingWithValue;

const ed25519NonSigningWithValue = {
  kind: 'non_signing',
  record: validEd25519SessionRecord,
  reason: 'cookie_session',
  value: validEd25519SigningWalletSession,
  // @ts-expect-error Non-signing Ed25519 persisted state cannot carry signing value.
} satisfies RouterAbEd25519PersistedSigningRecordState;
void ed25519NonSigningWithValue;

const ecdsaMissingRouterAbState = {
  ...validEcdsaSigningWalletSession,
  // @ts-expect-error Signable ECDSA-HSS Wallet Session state requires Router A/B normal-signing state.
  routerAbEcdsaHssNormalSigning: undefined,
} satisfies RouterAbEcdsaHssSigningWalletSession;
void ecdsaMissingRouterAbState;

const ecdsaMissingRuntimePolicyScope = {
  ...validEcdsaSigningWalletSession,
  // @ts-expect-error Signable ECDSA-HSS Wallet Session state requires runtime policy scope.
  runtimePolicyScope: undefined,
} satisfies RouterAbEcdsaHssSigningWalletSession;
void ecdsaMissingRuntimePolicyScope;

const ecdsaCookieAuth = {
  ...validEcdsaSigningWalletSession,
  auth: {
    // @ts-expect-error Signable ECDSA-HSS Wallet Session state is bearer Wallet Session JWT only.
    kind: 'browser_cookie',
  },
} satisfies RouterAbEcdsaHssSigningWalletSession;
void ecdsaCookieAuth;

const ecdsaRawClientShare = {
  ...validEcdsaSigningWalletSession,
  // @ts-expect-error Signable ECDSA-HSS Wallet Session state must not carry raw client signing shares.
  clientSigningShare32: new Uint8Array(32),
} satisfies RouterAbEcdsaHssSigningWalletSession;
void ecdsaRawClientShare;

const ecdsaRawClientVerifier = {
  ...validEcdsaSigningWalletSession,
  // @ts-expect-error Signable ECDSA-HSS Wallet Session state carries verifier material through signingMaterial.
  clientVerifyingShareB64u: 'raw-client-verifier',
} satisfies RouterAbEcdsaHssSigningWalletSession;
void ecdsaRawClientVerifier;

const ecdsaMissingSigningMaterial = {
  ...validEcdsaSigningWalletSession,
  // @ts-expect-error Signable ECDSA-HSS Wallet Session state requires parsed signing material.
  signingMaterial: undefined,
} satisfies RouterAbEcdsaHssSigningWalletSession;
void ecdsaMissingSigningMaterial;

const ecdsaSigningMaterialWithRawVerifier = {
  ...validEcdsaSigningWalletSession,
  signingMaterial: {
    ...ecdsaSigningMaterial,
    // @ts-expect-error Parsed ECDSA-HSS signing material rejects persisted verifier field names.
    clientVerifyingShareB64u: 'raw-client-verifier',
  },
} satisfies RouterAbEcdsaHssSigningWalletSession;
void ecdsaSigningMaterialWithRawVerifier;
