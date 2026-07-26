import type { D1WalletAddSignerFinalizePreparedV1 } from './d1WalletAddSignerService';

const validEd25519FinalizePrepared = {
  kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1',
  finalizingAtMs: 1,
  signingGrantId: 'grant-1',
  expiresAtMs: 2,
  remainingUses: 1,
} satisfies D1WalletAddSignerFinalizePreparedV1;

const validEcdsaFinalizePrepared = {
  kind: 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1',
  signerWriteAtMs: 1,
} satisfies D1WalletAddSignerFinalizePreparedV1;

const ecdsaFinalizeWithSessionTerms = {
  kind: 'd1_wallet_add_signer_finalize_ecdsa_prepared_v1',
  signerWriteAtMs: 1,
  // @ts-expect-error ECDSA finalization cannot carry Ed25519 session terms.
  signingGrantId: 'grant-1',
} satisfies D1WalletAddSignerFinalizePreparedV1;

const ed25519FinalizeWithoutSessionTerms = {
  kind: 'd1_wallet_add_signer_finalize_ed25519_prepared_v1',
  finalizingAtMs: 1,
  // @ts-expect-error Ed25519 finalization requires durable session terms.
} satisfies D1WalletAddSignerFinalizePreparedV1;

void validEd25519FinalizePrepared;
void validEcdsaFinalizePrepared;
void ecdsaFinalizeWithSessionTerms;
void ed25519FinalizeWithoutSessionTerms;
