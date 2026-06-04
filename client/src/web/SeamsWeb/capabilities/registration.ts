import type { RegistrationCapability } from '../interfaces';

export function createRegistrationCapability(
  handlers: RegistrationCapability,
): RegistrationCapability {
  return {
    addWalletSigner: async (args) => await handlers.addWalletSigner(args),
    registerWallet: async (args) => await handlers.registerWallet(args),
    registerWithEmailOtp: async (args) => await handlers.registerWallet(args),
    registerPasskey: async (nearAccountId, options) =>
      await handlers.registerPasskey(nearAccountId, options),
    registerPasskeyInternal: async (nearAccountId, options, confirmationConfigOverride) =>
      await handlers.registerPasskeyInternal(nearAccountId, options, confirmationConfigOverride),
  };
}
