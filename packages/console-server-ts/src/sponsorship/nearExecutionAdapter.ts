import {
  buildDelegateActionPolicyFromResolvedRule,
  type ResolvedSponsoredNearDelegatePolicy,
} from './near';
import type { ExecuteSignedDelegateRequest, ExecuteSignedDelegateResult } from '@seams/sdk-server/internal/delegateAction';
import type { SponsorshipExecutionAdapter } from './executionAdapter';

export interface SponsoredNearDelegateAuthService {
  executeSignedDelegate(input: ExecuteSignedDelegateRequest): Promise<ExecuteSignedDelegateResult>;
}

export type SponsoredNearDelegateExecutionResult = Awaited<
  ReturnType<SponsoredNearDelegateAuthService['executeSignedDelegate']>
>;

export type SponsoredNearDelegateExecutionAdapter = SponsorshipExecutionAdapter<
  SponsoredNearDelegateExecutionResult,
  'near_delegate',
  Record<string, never>
>;

export function createSponsoredNearDelegateExecutionAdapter(input: {
  authService: SponsoredNearDelegateAuthService;
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
