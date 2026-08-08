import type { NearSignerCapability } from '@/SeamsWeb/signingSurface/types';
import type {
  NearSigningWebContext,
  RegistrationCapability,
} from '@/SeamsWeb/signingSurface/types';
import {
  implicitNearAccountProvisioning,
  type RegisterWalletInput,
  type RegistrationNearAccountProvisioning,
} from '@shared/utils/registrationIntent';
import { buildNearWalletRegistrationSignerSetSelection } from '@/SeamsWeb/operations/registration/registrationSignerSet';

type NearWalletRegistrationArgs = Parameters<RegistrationCapability['registerWallet']>[0] & {
  options: NonNullable<Parameters<RegistrationCapability['registerWallet']>[0]['options']>;
};

function resolveNearRegistrationAccountProvisioning(
  args: Parameters<NearSignerCapability['registerNearWallet']>[0],
): RegistrationNearAccountProvisioning {
  if (!args.accountProvisioning || args.accountProvisioning.kind === 'implicit_account') {
    return args.accountProvisioning || implicitNearAccountProvisioning();
  }
  return args.accountProvisioning;
}

export function buildNearWalletRegistrationArgs(
  context: NearSigningWebContext,
  args: Parameters<NearSignerCapability['registerNearWallet']>[0],
): NearWalletRegistrationArgs {
  if (!args.authMethod) {
    throw new Error('[SeamsWeb][near] registerNearWallet requires an explicit authMethod');
  }
  const accountProvisioning = resolveNearRegistrationAccountProvisioning(args);
  let wallet: RegisterWalletInput;
  switch (accountProvisioning.kind) {
    case 'implicit_account':
      wallet = args.wallet || { kind: 'server_allocated' };
      break;
    case 'sponsored_named_account':
      if (!args.wallet) {
        throw new Error(
          '[SeamsWeb][near] sponsored NEAR registration requires a provided walletId',
        );
      }
      wallet = args.wallet;
      break;
    default:
      throw new Error('[SeamsWeb][near] unsupported NEAR account provisioning branch');
  }
  return {
    wallet,
    authMethod: args.authMethod,
    signerSelection: buildNearWalletRegistrationSignerSetSelection({
      configs: context.configs,
      accountProvisioning,
      options: args.options || {},
    }),
    options: args.options || {},
  };
}

export { signDelegateAction } from './delegateAction';
export { sendDelegateActionViaRelayer, delegateRelayerAuthFromConfigs } from './delegateAction';
export type { DelegateRelayerAuth } from './delegateAction';
export type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
