import type { WalletId } from './ecdsaChainTarget';
import type { NearSigningRuntimeDeps } from './runtime';
import type { Ed25519OperationStepUpProof } from '../threshold/ed25519/walletSession';

declare const resolveOperationStepUpCredential: NearSigningRuntimeDeps['resolveOperationStepUpCredential'];
declare const walletId: WalletId;
declare const operationStepUpProof: Ed25519OperationStepUpProof;

const operationStepUpCredential = resolveOperationStepUpCredential({
  walletId,
  relayerUrl: 'https://relay.example.test',
  proof: operationStepUpProof,
});
void operationStepUpCredential.then((credential) => {
  if (credential.kind !== 'wallet_session_opaque') return;
  const token: string = credential.walletSessionToken;
  void token;
});
