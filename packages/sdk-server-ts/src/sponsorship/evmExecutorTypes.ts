import type { SponsoredEvmCall } from './evm';
import type { SponsorshipExecutionAdapter } from './executionAdapter';

export type SponsoredEvmChainExecutorConfig = {
  chainId: number;
  rpcUrl: string;
  sponsorAddress: `0x${string}`;
  sponsorPrivateKeyHex: `0x${string}`;
  maxPriorityFeePerGasFloor: bigint;
  maxFeePerGasFloor: bigint;
};

export type SponsoredEvmCallExecutorConfig = {
  executorsByChain: ReadonlyMap<number, SponsoredEvmChainExecutorConfig>;
};

export type SponsoredEvmExecutionResult = {
  txHash: `0x${string}`;
  gasUsed: string;
  effectiveGasPrice: string;
  feeAmount: string;
};

export type SponsoredEvmExecutionAdapter = SponsorshipExecutionAdapter<
  SponsoredEvmExecutionResult,
  'evm_eoa',
  {
    chainId: number;
    sponsorAddress: `0x${string}`;
  }
>;

export type SponsoredEvmExecutionAdapterResolver = (input: {
  config: SponsoredEvmCallExecutorConfig;
  chainId: number;
  call: SponsoredEvmCall;
}) => SponsoredEvmExecutionAdapter | null;
