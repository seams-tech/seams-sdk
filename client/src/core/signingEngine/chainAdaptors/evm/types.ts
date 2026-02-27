export type Hex = `0x${string}`;

export type EvmAddress = Hex; // 20 bytes
export type EvmBytes = Hex; // 0x-prefixed hex bytes

export type EvmAbiParameter = {
  name?: string;
  type: string;
  components?: readonly EvmAbiParameter[];
};

export type EvmAbiEntry = {
  type?: string;
  name?: string;
  inputs?: readonly EvmAbiParameter[];
} & Record<string, unknown>;
export type EvmContractAbi = readonly EvmAbiEntry[];

export type EvmAccessListItem = {
  address: EvmAddress;
  storageKeys: Hex[]; // each 32 bytes
};

export type Eip1559UnsignedTx = {
  chainId: number;
  nonce?: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint;
  to?: EvmAddress | null; // null/undefined = contract creation
  value: bigint;
  data?: EvmBytes; // defaults to 0x
  abi?: EvmContractAbi; // optional ABI used for tx confirmer calldata decoding
  accessList?: EvmAccessListItem[]; // defaults to []
};

export type EvmSigningRequest = {
  chain: 'evm';
  kind: 'eip1559';
  tx: Eip1559UnsignedTx;
  senderSignatureAlgorithm: 'secp256k1';
};

export type EvmSecp256k1SigningRequest = EvmSigningRequest;
