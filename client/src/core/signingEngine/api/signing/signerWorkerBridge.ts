import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { ActionArgsWasm } from '@/core/types/actions';
import type {
  NearIntentResult,
  NearSigningRequest,
} from '../../interfaces/near';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';

export type SignerWorkerBridgeDeps = {
  signingKeyOps: Pick<
    NearSigningKeyOps,
    'extractCosePublicKey' | 'signTransactionWithKeyPair' | 'generateEphemeralNearKeypair'
  >;
};

export async function signNearWithIntent<TRequest extends NearSigningRequest>(
  request: TRequest,
): Promise<NearIntentResult<TRequest>> {
  const { signNearWithSecureConfirm } = await import('../../orchestration/near/nearSigningFlow');
  return await signNearWithSecureConfirm(request);
}

export async function extractCosePublicKey(
  deps: SignerWorkerBridgeDeps,
  attestationObjectBase64url: string,
): Promise<Uint8Array> {
  return await deps.signingKeyOps.extractCosePublicKey(attestationObjectBase64url);
}

export async function signTransactionWithKeyPair(
  deps: SignerWorkerBridgeDeps,
  args: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  },
): Promise<{
  signedTransaction: SignedTransaction;
  logs?: string[];
}> {
  return await deps.signingKeyOps.signTransactionWithKeyPair({
    nearPrivateKey: args.nearPrivateKey,
    signerAccountId: args.signerAccountId,
    receiverId: args.receiverId,
    nonce: args.nonce,
    blockHash: args.blockHash,
    actions: args.actions,
  });
}

export async function generateEphemeralNearKeypair(
  deps: SignerWorkerBridgeDeps,
): Promise<{ publicKey: string; privateKey: string }> {
  return await deps.signingKeyOps.generateEphemeralNearKeypair();
}
