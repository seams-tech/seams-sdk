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
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';

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

function requireNearRegistrationRpId(value: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

export function buildNearWalletRegistrationArgs(
  context: NearSigningWebContext,
  args: Parameters<NearSignerCapability['registerNearWallet']>[0],
): NearWalletRegistrationArgs {
  const rpId = requireNearRegistrationRpId(context.signingEngine.getRpId());
  if (!rpId) {
    throw new Error('[SeamsWeb][near] registerNearWallet requires rpId');
  }
  const authMethod = args.authMethod || { kind: 'passkey' as const, rpId };
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
    authMethod,
    signerSelection: buildNearWalletRegistrationSignerSetSelection({
      configs: context.configs,
      accountProvisioning,
      options: args.options || {},
    }),
    options: args.options || {},
  };
}

export { signDelegateAction } from './delegateAction';
export { sendDelegateActionViaRelayer } from './delegateAction';
export type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
