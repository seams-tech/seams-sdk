import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import { IndexedDBManager } from '@/core/indexedDB';
import type { EmailOtpVerifiedAuthorityProjection } from '@/core/signingEngine/session/emailOtp/publicTypes';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { isActiveRecoveredWalletAuthorityV1 } from '@shared/authorization/walletAuthority';

export async function persistVerifiedEmailOtpAuthorityAfterUnlock(args: {
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly projection: EmailOtpVerifiedAuthorityProjection;
}): Promise<void> {
  const { authority, authMethod } = args.projection;
  if (
    String(authority.walletId) !== args.walletId ||
    String(authMethod.walletId) !== args.walletId ||
    String(authMethod.walletAuthMethodId) !== args.walletAuthMethodId ||
    String(authMethod.walletAuthorityId) !== String(authority.authorityId)
  ) {
    throw new Error('Verified Email OTP authority changed during wallet unlock');
  }
  switch (authority.provenance.kind) {
    case 'wallet_registration':
      await IndexedDBManager.persistFoundingWalletAuthority({ authority, authMethod });
      return;
    case 'wallet_recovery': {
      if (!isActiveRecoveredWalletAuthorityV1(authority)) {
        throw new Error('Recovered Email OTP authority provenance is invalid');
      }
      const local = await IndexedDBManager.resolveWalletAuthorityForMethod(
        args.walletId,
        args.walletAuthMethodId,
      );
      const mismatches =
        local.kind !== 'resolved'
          ? [`resolution:${local.kind}`]
          : [
              ...(String(local.authority.authorityId) !== String(authority.authorityId)
                ? ['authorityId']
                : []),
              ...(String(local.authority.authorityDigestB64u) !==
              String(authority.authorityDigestB64u)
                ? ['authorityDigest']
                : []),
              ...(local.authMethod.kind !== 'email_otp' ? ['method.kind'] : []),
              ...(local.authMethod.status !== 'active' ? ['method.status'] : []),
              ...(String(local.authMethod.walletAuthMethodId) !==
              String(authMethod.walletAuthMethodId)
                ? ['method.id']
                : []),
              ...(String(local.authMethod.walletAuthorityId) !==
              String(authMethod.walletAuthorityId)
                ? ['method.authorityId']
                : []),
              ...(local.authMethod.kind === 'email_otp' &&
              local.authMethod.emailHashHex !== authMethod.emailHashHex
                ? ['method.emailHash']
                : []),
              /* No registrationAuthorityId equality: a sibling added to the
                 recovered authority stores the provider identity there by the
                 add projection's convention, while the server names the add
                 challenge. The authority digest and method identity above
                 already prove the local install. */
            ];
      if (mismatches.length > 0) {
        throw new Error(
          `Verified recovered Email OTP authority is not installed on this device: ${mismatches.join(', ')}`,
        );
      }
      return;
    }
    case 'device_link': {
      const local = await IndexedDBManager.resolveWalletAuthorityForMethod(
        args.walletId,
        args.walletAuthMethodId,
      );
      if (
        local.kind !== 'resolved' ||
        String(local.authority.authorityId) !== String(authority.authorityId) ||
        String(local.authority.authorityDigestB64u) !== String(authority.authorityDigestB64u)
      ) {
        throw new Error('Verified linked Email OTP authority is not installed on this device');
      }
      return;
    }
  }
  authority.provenance satisfies never;
}

export async function walletAuthAuthorityRefForVerifiedEmailOtpUnlock(args: {
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly providerSubject: string;
  readonly emailHashHex: string;
  readonly projection: EmailOtpVerifiedAuthorityProjection;
}): Promise<WalletAuthAuthorityRef> {
  const { authority, authMethod } = args.projection;
  if (
    String(authority.walletId) !== args.walletId ||
    String(authMethod.walletId) !== args.walletId ||
    String(authMethod.walletAuthMethodId) !== args.walletAuthMethodId ||
    String(authMethod.walletAuthorityId) !== String(authority.authorityId) ||
    authMethod.emailHashHex !== args.emailHashHex
  ) {
    throw new Error('Verified Email OTP authority does not match the wallet unlock factor');
  }
  const base = buildEmailOtpWalletAuthAuthority({
    walletId: args.walletId,
    provider: args.providerSubject.startsWith('google:') ? 'google' : 'email',
    providerUserId: args.providerSubject,
    emailHashHex: args.emailHashHex,
  });
  return await walletAuthAuthorityRef({
    authority: {
      walletId: base.walletId,
      factor: base.factor,
      verifier: base.verifier,
      bindingId: authMethod.walletAuthMethodId,
    },
  });
}

export type EmailOtpWalletPostUnlockActivation =
  | {
      kind: 'near_ed25519_wallet';
      signer: NearEd25519SignerBinding;
      walletAuthMethodId: WalletAuthMethodId;
      walletId?: never;
    }
  | {
      kind: 'evm_family_ecdsa_wallet';
      walletId: WalletId;
      walletAuthMethodId: WalletAuthMethodId;
      signer?: never;
    };

export type EmailOtpWalletPostUnlockActivationDeps = {
  signingEngine: {
    setWalletAuthenticated(args: {
      kind: 'authenticated';
      walletId: WalletId;
      authMethod: 'email_otp';
    }): void;
    activateAuthenticatedWalletState(args: {
      walletId: WalletId;
      nearAccountId: ReturnType<typeof toAccountId>;
      signerSlot: number;
      nearClient?: NearClient;
    }): Promise<void>;
    markSelectedEmailOtpWalletAuthorityUnlocked(input: {
      walletId: WalletId;
      walletAuthMethodId: WalletAuthMethodId;
    }): Promise<void>;
    getUserPreferences(): {
      setCurrentWallet(walletId: WalletId): void;
      reloadUserSettings(): Promise<void>;
    };
  };
  nearClient?: NearClient;
};

function ignoreUserPreferenceReloadError(): undefined {
  return undefined;
}

export async function activateEmailOtpWalletAfterUnlock(
  deps: EmailOtpWalletPostUnlockActivationDeps,
  activation: EmailOtpWalletPostUnlockActivation,
): Promise<void> {
  switch (activation.kind) {
    case 'near_ed25519_wallet':
      await deps.signingEngine.activateAuthenticatedWalletState({
        walletId: activation.signer.account.wallet.walletId,
        nearAccountId: toAccountId(activation.signer.account.nearAccountId),
        signerSlot: activation.signer.signerSlot,
        ...(deps.nearClient ? { nearClient: deps.nearClient } : {}),
      });
      await deps.signingEngine.markSelectedEmailOtpWalletAuthorityUnlocked({
        walletId: activation.signer.account.wallet.walletId,
        walletAuthMethodId: activation.walletAuthMethodId,
      });
      deps.signingEngine.setWalletAuthenticated({
        kind: 'authenticated',
        walletId: activation.signer.account.wallet.walletId,
        authMethod: 'email_otp',
      });
      return;
    case 'evm_family_ecdsa_wallet': {
      const preferences = deps.signingEngine.getUserPreferences();
      preferences.setCurrentWallet(activation.walletId);
      await preferences.reloadUserSettings().catch(ignoreUserPreferenceReloadError);
      await deps.signingEngine.markSelectedEmailOtpWalletAuthorityUnlocked({
        walletId: activation.walletId,
        walletAuthMethodId: activation.walletAuthMethodId,
      });
      deps.signingEngine.setWalletAuthenticated({
        kind: 'authenticated',
        walletId: activation.walletId,
        authMethod: 'email_otp',
      });
      return;
    }
  }
  activation satisfies never;
}
