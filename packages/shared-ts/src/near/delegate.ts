import type { ActionArgs } from './actions';

export interface PublicKey {
  keyType: number;
  keyData: number[];
}

export interface Signature {
  keyType: number;
  signatureData: number[];
}

export interface DelegateAction {
  senderId: string;
  receiverId: string;
  actions: ActionArgs[];
  nonce: bigint | string | number;
  maxBlockHeight: bigint | string | number;
  publicKey: PublicKey;
}

export interface SignedDelegate {
  delegateAction: DelegateAction;
  signature: Signature;
}

export interface DelegateActionInput {
  senderId: string;
  receiverId: string;
  actions: ActionArgs[];
  nonce: bigint | string | number;
  maxBlockHeight: bigint | string | number;
  publicKey: string | PublicKey;
}
