import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { ActionArgsWasm } from '@/core/types/actions';
import type { NearSigningKeyOps } from '@/core/signingEngine/interfaces/nearKeyOps';

export type NearEphemeralKeyHandleSigningInput = {
  keyHandle: string;
  signerAccountId: string;
  receiverId: string;
  nonce: string;
  blockHash: string;
  actions: ActionArgsWasm[];
};

export type NearEphemeralKeypair = {
  publicKey: string;
  keyHandle: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type NearKeyOperationsService = {
  signTransactionWithEphemeralNearKeypairHandle(input: NearEphemeralKeyHandleSigningInput): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }>;
  generateEphemeralNearKeypairHandle(input: { expiresAtMs: number }): Promise<NearEphemeralKeypair>;
};

export type NearKeyOperationsPort = Pick<
  NearSigningKeyOps,
  'signTransactionWithEphemeralNearKeypairHandle' | 'generateEphemeralNearKeypairHandle'
>;

export function createNearKeyOperationsService(
  nearKeyOps: NearKeyOperationsPort,
): NearKeyOperationsService {
  return {
    signTransactionWithEphemeralNearKeypairHandle: (input) =>
      nearKeyOps.signTransactionWithEphemeralNearKeypairHandle(input),
    generateEphemeralNearKeypairHandle: (input) =>
      nearKeyOps.generateEphemeralNearKeypairHandle(input),
  };
}
