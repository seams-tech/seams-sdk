import type { WalletId } from './ecdsaChainTarget';
import type { NearSigningRuntimeDeps } from './runtime';
import type { RouterAbEd25519NormalSigningCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';

declare const resolvePasskeyOperationStepUpCredential: NearSigningRuntimeDeps['resolvePasskeyOperationStepUpCredential'];
declare const walletId: WalletId;

const passkeyJwtCredential = resolvePasskeyOperationStepUpCredential({
  walletId,
  relayerUrl: 'https://relay.example.test',
});
if (passkeyJwtCredential.kind === 'app_session_jwt') {
  const jwt: string = passkeyJwtCredential.appSessionJwt;
  void jwt;
}

const directModeCookieCredential = {
  kind: 'app_session_cookie',
} satisfies RouterAbEd25519NormalSigningCredential;
void directModeCookieCredential;
