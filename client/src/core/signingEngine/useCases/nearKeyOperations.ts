import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { ActionArgsWasm } from '@/core/types/actions';
import type { NearSigningKeyOps } from '@/core/signingEngine/interfaces/nearKeyOps';

export type NearTransactionKeyPairSigningInput = {
  nearPrivateKey: string;
  signerAccountId: string;
  receiverId: string;
  nonce: string;
  blockHash: string;
  actions: ActionArgsWasm[];
};

export type NearEphemeralKeypair = {
  publicKey: string;
  privateKey: string;
};

export type NearKeyOperationsService = {
  signTransactionWithKeyPair(input: NearTransactionKeyPairSigningInput): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }>;
  generateEphemeralNearKeypair(): Promise<NearEphemeralKeypair>;
};

export type NearKeyOperationsPort = Pick<
  NearSigningKeyOps,
  'signTransactionWithKeyPair' | 'generateEphemeralNearKeypair'
>;

export function createNearKeyOperationsService(
  nearKeyOps: NearKeyOperationsPort,
): NearKeyOperationsService {
  return {
    signTransactionWithKeyPair: (input) => nearKeyOps.signTransactionWithKeyPair(input),
    generateEphemeralNearKeypair: () => nearKeyOps.generateEphemeralNearKeypair(),
  };
}
