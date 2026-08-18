import type {
  EvmAccessListItem,
  EvmAddress,
  EvmBytes,
  EvmContractAbi,
  Hex,
  EvmSecp256k1SigningRequest,
  EvmSigningRequest,
} from '../evm/evmSigning.types';

export type TempoRlpValue = Uint8Array | TempoRlpValue[];

export type TempoCall = {
  to: EvmAddress; // 20 bytes
  value: bigint; // wei
  input?: EvmBytes; // calldata, defaults to 0x
  abi?: EvmContractAbi; // optional ABI used for tx confirmer calldata decoding
};

export type TempoFeePayerSignature =
  | { kind: 'none' }
  | { kind: 'placeholder' }
  | { kind: 'signed'; v: 0 | 1; r: Hex; s: Hex };

export type TempoUnsignedTx = {
  chainId: number;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
  calls: TempoCall[]; // must be non-empty
  accessList?: EvmAccessListItem[];
  nonceKey: bigint;
  nonce?: bigint;
  validBefore?: bigint | null;
  validAfter?: bigint | null;
  feeToken?: EvmAddress | null;
  feePayerSignature?: TempoFeePayerSignature;
  aaAuthorizationList?: TempoRlpValue; // default []
  keyAuthorization?: TempoRlpValue; // optional; omitted when undefined
};

export type TempoSigningRequest = {
  chain: 'tempo';
  kind: 'tempoTransaction';
  tx: TempoUnsignedTx;
  senderSignatureAlgorithm: 'secp256k1' | 'webauthnP256';
};

export type TempoSecp256k1SigningRequest = Extract<
  TempoSigningRequest,
  { senderSignatureAlgorithm: 'secp256k1' }
>;

export type MultichainSigningRequest = EvmSigningRequest | TempoSigningRequest;

export type MultichainSecp256k1SigningRequest =
  | EvmSecp256k1SigningRequest
  | TempoSecp256k1SigningRequest;
