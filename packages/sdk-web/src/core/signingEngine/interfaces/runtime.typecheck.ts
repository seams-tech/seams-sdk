import type { WalletId } from './ecdsaChainTarget';
import type { NearSigningRuntimeDeps } from './runtime';
import type { RouterAbEd25519NormalSigningCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';
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
  if (credential.kind !== 'app_session_jwt') return;
  const jwt: string = credential.appSessionJwt;
  void jwt;
});

const directModeCookieCredential = {
  kind: 'app_session_cookie',
} satisfies RouterAbEd25519NormalSigningCredential;
void directModeCookieCredential;
