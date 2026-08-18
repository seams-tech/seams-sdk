import type {
  WalletCustodyEd25519MaterialBindingV1,
  WalletCustodySealedEd25519MaterialV1,
} from './ed25519SeedMaterial';
import { WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND } from './ed25519SeedMaterial';

/**
 * What a wallet custody material record may and may not name.
 *
 * Compile-time, because these are absences: a runtime test can only check the
 * fields a record *has*, and the property here is which ones it can never
 * carry. Invalid states must fail to compile.
 *
 * Two families are excluded, for different reasons.
 *
 * **Authorization identity** — `AuthorizationGrantRef`, `WalletSessionId`,
 * `MpcWalletSigningQuotaId`, `AuthorizedOperationId`, bearer sessions. A
 * material handle is a key, not a permission; Refactor 90 owns those and
 * resolves them per operation. One embedded here would be a second source for
 * an identity that must have exactly one, and it would outlive the operation
 * it was minted for.
 *
 * **Factor identity** — `rpId`, `credentialIdB64u`, enrollment ids. The record
 * is sealed under the wallet custody seed so that a factor enrolled later
 * opens it too. Naming the credential that happened to run the ceremony would
 * put back the coupling this refactor removes.
 */

declare const binding: WalletCustodyEd25519MaterialBindingV1;
declare const sealed: WalletCustodySealedEd25519MaterialV1;

// The shape a real record carries: key-set identity and nothing else.
const wellFormed: WalletCustodyEd25519MaterialBindingV1 = {
  kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  applicationBindingDigestB64u: binding.applicationBindingDigestB64u,
  registeredPublicKeyB64u: binding.registeredPublicKeyB64u,
  participantIds: [1, 2],
  stateEpoch: '1',
  walletId: 'alice.testnet',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'near-ed25519-key-1',
  signerSlot: 1,
  signingWorkerId: 'signing-worker-1',
  signingWorkerVerifyingShareB64u: binding.signingWorkerVerifyingShareB64u,
};
void wellFormed;

const bindingWithGrant: WalletCustodyEd25519MaterialBindingV1 = {
  ...binding,
  // @ts-expect-error A material handle never carries an authorization grant.
  authorizationGrantRef: 'grant',
};
void bindingWithGrant;

const bindingWithWalletSession: WalletCustodyEd25519MaterialBindingV1 = {
  ...binding,
  // @ts-expect-error A material handle never carries a Wallet Session identity.
  walletSessionId: 'session',
};
void bindingWithWalletSession;

const bindingWithQuota: WalletCustodyEd25519MaterialBindingV1 = {
  ...binding,
  // @ts-expect-error A material handle never carries a signing quota.
  mpcWalletSigningQuotaId: 'quota',
};
void bindingWithQuota;

const bindingWithOperation: WalletCustodyEd25519MaterialBindingV1 = {
  ...binding,
  // @ts-expect-error A material handle never carries an authorized operation.
  authorizedOperationId: 'operation',
};
void bindingWithOperation;

const bindingWithCredential: WalletCustodyEd25519MaterialBindingV1 = {
  ...binding,
  // @ts-expect-error The record is wallet-scoped: it names no credential.
  credentialIdB64u: 'credential',
};
void bindingWithCredential;

const bindingWithRpId: WalletCustodyEd25519MaterialBindingV1 = {
  ...binding,
  // @ts-expect-error The record is wallet-scoped: it names no relying party.
  rpId: 'example.localhost',
};
void bindingWithRpId;

const bindingWithEnrollment: WalletCustodyEd25519MaterialBindingV1 = {
  ...binding,
  // @ts-expect-error The record is wallet-scoped: it names no OTP enrollment.
  enrollmentId: 'enrollment-1',
};
void bindingWithEnrollment;

// The sealed half is ciphertext and a nonce. A plaintext share here would be
// the whole point of sealing, undone.
const sealedWithPlaintext: WalletCustodySealedEd25519MaterialV1 = {
  ...sealed,
  // @ts-expect-error Sealed material never carries a plaintext scalar share.
  clientScalarShareB64u: 'share',
};
void sealedWithPlaintext;

// The seed itself must never reach a stored record: it is the wallet's whole
// custody, and the record is only a cache of one key set's material.
const sealedWithSeed: WalletCustodySealedEd25519MaterialV1 = {
  ...sealed,
  // @ts-expect-error A cache record never carries the wallet custody seed.
  custodySeedB64u: 'seed',
};
void sealedWithSeed;
