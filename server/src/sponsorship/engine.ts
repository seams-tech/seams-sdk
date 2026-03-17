import type { AuthService } from '../core/AuthService';
import type { SponsoredEvmCall } from './evm';
import {
  executeSponsoredEvmCall,
  resolveSponsoredEvmExecutorForChain,
  type SponsoredEvmCallExecutorConfig,
} from './evmRelay';
import {
  buildDelegateActionPolicyFromResolvedRule,
  type ResolvedSponsoredNearDelegatePolicy,
} from './near';

export interface SponsorshipExecutionAdapter<TResult, TKind extends string, TMeta> {
  executorKind: TKind;
  meta: TMeta;
  execute: () => Promise<TResult>;
}

export type SponsoredEvmExecutionResult = Awaited<
  ReturnType<typeof executeSponsoredEvmCall>
>;

export type SponsoredEvmExecutionAdapter = SponsorshipExecutionAdapter<
  SponsoredEvmExecutionResult,
  'evm_eoa',
  {
    chainId: number;
    sponsorAddress: `0x${string}`;
  }
>;

export type SponsoredNearDelegateExecutionResult = Awaited<
  ReturnType<AuthService['executeSignedDelegate']>
>;

export type SponsoredNearDelegateExecutionAdapter = SponsorshipExecutionAdapter<
  SponsoredNearDelegateExecutionResult,
  'near_delegate',
  Record<string, never>
>;

export function resolveSponsoredEvmExecutionAdapter(input: {
  config: SponsoredEvmCallExecutorConfig;
  chainId: number;
  call: SponsoredEvmCall;
}): SponsoredEvmExecutionAdapter | null {
  const executor = resolveSponsoredEvmExecutorForChain(input.config, input.chainId);
  if (!executor) return null;
  return {
    executorKind: 'evm_eoa',
    meta: {
      chainId: executor.chainId,
      sponsorAddress: executor.sponsorAddress,
    },
    execute: async () =>
      await executeSponsoredEvmCall({
        executor,
        call: input.call,
      }),
  };
}

export function createSponsoredNearDelegateExecutionAdapter(input: {
  authService: AuthService;
  hash: string;
  signedDelegate: unknown;
  allowedDelegateAction: ResolvedSponsoredNearDelegatePolicy['allowedDelegateActions'][number];
}): SponsoredNearDelegateExecutionAdapter {
  return {
    executorKind: 'near_delegate',
    meta: {},
    execute: async () =>
      await input.authService.executeSignedDelegate({
        hash: input.hash,
        signedDelegate: input.signedDelegate as any,
        policy: buildDelegateActionPolicyFromResolvedRule({
          allowedDelegateAction: input.allowedDelegateAction,
        }),
      }),
  };
}

export async function executeSponsorshipAdapter<TResult, TKind extends string, TMeta>(
  adapter: SponsorshipExecutionAdapter<TResult, TKind, TMeta>,
): Promise<TResult> {
  return await adapter.execute();
}
