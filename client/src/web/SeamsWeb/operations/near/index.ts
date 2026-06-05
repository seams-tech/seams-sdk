import { toAccountId } from '@/core/types/accountIds';
import type { NearSignerCapability } from '@/web/SeamsWeb/signingSurface/types';
import type { NearSigningWebContext, RegistrationCapability } from '@/web/SeamsWeb/signingSurface/types';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { buildPasskeyNearWalletRegistrationSignerSelection } from '@/web/SeamsWeb/operations/registration/registrationSignerSelection';

type NearWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0] & {
  options: NonNullable<Parameters<RegistrationCapability['registerWallet']>[0]['options']>;
};

export function buildNearWalletRegistrationArgs(
  context: NearSigningWebContext,
  args: Parameters<NearSignerCapability['registerNearWallet']>[0],
): NearWalletRegistrationArgs {
  const accountId = toAccountId(args.nearAccountId);
  const rpId = context.signingEngine.getRpId();
  if (!rpId) {
    throw new Error('[SeamsWeb][near] registerNearWallet requires rpId');
  }
  const authMethod = args.authMethod || { kind: 'passkey' as const };
  return {
    wallet: {
      kind: 'provided',
      walletId: walletIdFromString(String(accountId)),
    },
    rpId,
    authMethod,
    signerSelection: buildPasskeyNearWalletRegistrationSignerSelection({
      configs: context.configs,
      nearAccountId: String(accountId),
      options: args.options || {},
    }),
    options: args.options || {},
  };
}

export { signDelegateAction } from './delegateAction';
export { sendDelegateActionViaRelayer } from './delegateAction';
export type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
