import type {
  NearSignerCapability,
  NearSigningSurface,
  NearSigningWebContext,
  RegistrationSigningSurface,
  RegistrationWebContext,
  UserAccountLookupSurface,
} from '@/SeamsWeb/signingSurface/types';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import { toError } from '@shared/utils/errors';
import { toAccountId } from '@/core/types/accountIds';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import {
  executeAction,
  sendTransaction,
  signAndSendTransaction,
  signTransactionWithActions,
} from '@/SeamsWeb/operations/near/actions';
import {
  delegateRelayerAuthFromConfigs,
  sendDelegateActionViaRelayer as sendDelegateActionViaRelayerCore,
  signDelegateAction as signDelegateActionCore,
} from '@/SeamsWeb/operations/near/delegateAction';
import { signNEP413Message as signNEP413MessageCore } from '@/SeamsWeb/operations/near/signNEP413';
import { buildNearWalletRegistrationArgs } from '@/SeamsWeb/operations/near';
import { registerWallet as registerWalletWithUnifiedCeremony } from '@/SeamsWeb/operations/registration/registration';
import { resolveNearCommandSubject } from '@/SeamsWeb/operations/near/commandSubject';
import { fundImplicitNearAccountForTesting } from '@/core/rpcClients/relayer/walletRegistration';
import {
  walletSessionAuthorizations,
  type WalletCapabilitySubjectV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { IndexedDBManager } from '@/core/indexedDB';
import type {
  NearAccountRef,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  CAPABILITY_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  type NearEd25519MpcOperationKind,
} from '@shared/authorization/capabilityKinds';
import { requireBrowserCapabilityOperation } from '@/SeamsWeb/publicApi/capabilitySelection';
import type { CurrentWalletResolver } from '@/SeamsWeb/publicApi/currentWallet';

function relayerUrlFromConfigs(configs: SeamsConfigsReadonly): string {
  const relayerUrl = String(configs.network.relayer?.url || '').trim();
  if (!relayerUrl) throw new Error('Relayer URL is not configured');
  return relayerUrl;
}

function requireNearPublicKey(value: unknown): string {
  const nearPublicKey = String(value || '').trim();
  if (!nearPublicKey) throw new Error('NEAR public key is required');
  return nearPublicKey;
}

function requireNearSigningCapability(
  configs: SeamsConfigsReadonly,
  operationKind: NearEd25519MpcOperationKind,
): void {
  requireBrowserCapabilityOperation(configs, {
    capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
    operationKind,
  });
}

function hasEd25519SigningSubject(subjects: readonly WalletCapabilitySubjectV1[]): boolean {
  for (const subject of subjects) {
    if (subject.kind === 'sign' && subject.keyFamily === 'ed25519') return true;
  }
  return false;
}

async function requireCurrentEd25519WalletSessionToken(
  walletSession: WalletSessionRef,
): Promise<string> {
  const selected = await IndexedDBManager.resolveSelectedWalletAuthority(
    String(walletSession.walletId),
  );
  if (selected.kind !== 'resolved') {
    throw new Error('Current Ed25519 wallet session is required for implicit NEAR funding');
  }
  const { selection, authMethod, authority } = selected;
  if (
    selection.lockState !== 'unlocked' ||
    selection.walletId !== walletSession.walletId ||
    selection.walletAuthMethodId !== authMethod.walletAuthMethodId ||
    authMethod.walletId !== walletSession.walletId ||
    authMethod.walletAuthorityId !== authority.authorityId ||
    authMethod.status !== 'active' ||
    authority.walletId !== walletSession.walletId ||
    authority.state !== 'active'
  ) {
    throw new Error('Current Ed25519 wallet session is required for implicit NEAR funding');
  }
  const read = await walletSessionAuthorizations.readExactWithOperationCredential({
    walletId: walletSession.walletId,
    authorityId: authority.authorityId,
    authMethodId: authMethod.walletAuthMethodId,
  });
  if (
    read.kind !== 'found' ||
    read.record.authorityDigestB64u !== authority.authorityDigestB64u ||
    read.record.authorityRevocationEpoch !== authority.revocationEpoch ||
    read.record.expiresAtMs <= Date.now() ||
    !hasEd25519SigningSubject(read.record.capabilitySubjects)
  ) {
    throw new Error('Current Ed25519 wallet session is required for implicit NEAR funding');
  }
  return read.operationCredential.token;
}

export async function fundImplicitNearAccountFromCurrentSession(args: {
  configs: SeamsConfigsReadonly;
  walletSession: WalletSessionRef;
  nearAccount: NearAccountRef;
  nearPublicKey: string;
}): ReturnType<typeof fundImplicitNearAccountForTesting> {
  return await fundImplicitNearAccountForTesting({
    relayerUrl: relayerUrlFromConfigs(args.configs),
    walletId: args.walletSession.walletId,
    nearAccountId: args.nearAccount.accountId,
    nearPublicKeyStr: requireNearPublicKey(args.nearPublicKey),
    walletSessionToken: await requireCurrentEd25519WalletSessionToken(args.walletSession),
  });
}

export function createNearSignerCapability(deps: {
  signingEngine: RegistrationSigningSurface & NearSigningSurface & UserAccountLookupSurface;
  nearClient: NearSigningWebContext['nearClient'];
  configs: SeamsConfigsReadonly;
  getTheme: () => ThemeMode;
  getWalletIframe: () => WalletIframeCoordinator;
  currentWallet: CurrentWalletResolver;
}): NearSignerCapability {
  const getContext = (): NearSigningWebContext => ({
    signingEngine: deps.signingEngine,
    nearClient: deps.nearClient,
    configs: deps.configs,
    theme: deps.getTheme(),
  });
  const nearCapability: NearSignerCapability = {
    registerNearWallet: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const context = getContext();
      const registerWalletArgs = buildNearWalletRegistrationArgs(context, args);
      if (!walletIframe.shouldUseWalletIframe()) {
        const registrationContext: RegistrationWebContext = {
          signingEngine: deps.signingEngine,
          nearClient: deps.nearClient,
          configs: deps.configs,
          theme: deps.getTheme(),
        };
        return await registerWalletWithUnifiedCeremony({
          context: registrationContext,
          ...registerWalletArgs,
          authenticatorOptions: cloneAuthenticatorOptions(
            deps.configs.webauthn.authenticatorOptions,
          ),
        });
      }
      try {
        const walletRouterId =
          registerWalletArgs.wallet.kind === 'provided'
            ? String(registerWalletArgs.wallet.walletId)
            : undefined;
        const router = await walletIframe.requireRouter(walletRouterId);
        const result = await router.registerWallet(registerWalletArgs);
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    fundImplicitNearAccountForTesting: async (args) => {
      const walletIframe = deps.getWalletIframe();
      const commandSubject = resolveNearCommandSubject({
        nearAccountId: args.nearAccount.accountId,
        walletSession: args.walletSession,
      });
      if (!walletIframe.shouldUseWalletIframe()) {
        return await fundImplicitNearAccountFromCurrentSession({
          configs: deps.configs,
          walletSession: commandSubject.walletSession,
          nearAccount: args.nearAccount,
          nearPublicKey: args.nearPublicKey,
        });
      }
      const router = await walletIframe.requireRouter(commandSubject.walletSession.walletId);
      return await router.fundImplicitNearAccountForTesting({
        walletId: commandSubject.walletSession.walletId,
        nearAccountId: args.nearAccount.accountId,
        nearPublicKey: args.nearPublicKey,
      });
    },
    executeAction: async (rawArgs) => {
      // `walletSession`/`nearAccount` are optional on the public surface: omitted,
      // they resolve to the authenticated wallet. `options` normalizes to `{}` so
      // every hook site below can stay unconditional.
      const args = {
        ...rawArgs,
        ...(await deps.currentWallet.nearSubject(rawArgs)),
        options: rawArgs.options ?? {},
      };
      requireNearSigningCapability(deps.configs, NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction);
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const commandSubject = resolveNearCommandSubject({
        nearAccountId,
        walletSession: args.walletSession,
      });
      if (!walletIframe.shouldUseWalletIframe()) {
        return await executeAction({
          context: getContext(),
          nearAccountId,
          walletSession: commandSubject.walletSession,
          receiverId: toAccountId(args.receiverId),
          actionArgs: args.actionArgs,
          options: args.options,
        });
      }
      try {
        const router = await walletIframe.requireRouter(commandSubject.walletSession.walletId);
        const result = await router.executeAction({
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          receiverId: args.receiverId,
          actionArgs: args.actionArgs,
          options: args.options,
        });
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    signAndSendTransaction: async (rawArgs) => {
      // `walletSession`/`nearAccount` are optional on the public surface: omitted,
      // they resolve to the authenticated wallet. `options` normalizes to `{}` so
      // every hook site below can stay unconditional.
      const args = {
        ...rawArgs,
        ...(await deps.currentWallet.nearSubject(rawArgs)),
        options: rawArgs.options ?? {},
      };
      requireNearSigningCapability(deps.configs, NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction);
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const commandSubject = resolveNearCommandSubject({
        nearAccountId,
        walletSession: args.walletSession,
      });
      const transaction = {
        receiverId: args.receiverId,
        actions: args.actions,
      };
      if (!walletIframe.shouldUseWalletIframe()) {
        try {
          return await signAndSendTransaction({
            context: getContext(),
            nearAccountId,
            walletSession: commandSubject.walletSession,
            transactionInput: transaction,
            options: args.options,
          });
        } catch (error: unknown) {
          const e = toError(error);
          await args.options?.afterCall?.(false, undefined, e);
          throw e;
        }
      }
      try {
        const router = await walletIframe.requireRouter(commandSubject.walletSession.walletId);
        const result = await router.signAndSendTransaction({
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          transaction,
          options: args.options,
        });
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    signTransactionWithActions: async (rawArgs) => {
      // `walletSession`/`nearAccount` are optional on the public surface: omitted,
      // they resolve to the authenticated wallet. `options` normalizes to `{}` so
      // every hook site below can stay unconditional.
      const args = {
        ...rawArgs,
        ...(await deps.currentWallet.nearSubject(rawArgs)),
        options: rawArgs.options ?? {},
      };
      requireNearSigningCapability(deps.configs, NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction);
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const commandSubject = resolveNearCommandSubject({
        nearAccountId,
        walletSession: args.walletSession,
      });
      const { transaction, options } = args;
      if (!walletIframe.shouldUseWalletIframe()) {
        try {
          return await signTransactionWithActions({
            context: getContext(),
            nearAccountId,
            walletSession: commandSubject.walletSession,
            transactionInput: transaction,
            options,
          });
        } catch (error: unknown) {
          const e = toError(error);
          await options?.afterCall?.(false, undefined, e);
          throw e;
        }
      }
      try {
        const router = await walletIframe.requireRouter(commandSubject.walletSession.walletId);
        const result = await router.signTransactionWithActions({
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          transaction: {
            receiverId: transaction.receiverId,
            actions: transaction.actions,
          },
          options: {
            signerSlot: options.signerSlot,
            onEvent: options.onEvent,
            confirmationConfig: options.confirmationConfig,
            confirmerText: options.confirmerText,
          },
        });
        await options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    sendTransaction: async (rawArgs) => {
      const args = { ...rawArgs, ...(await deps.currentWallet.nearSubject(rawArgs)) };
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const commandSubject = resolveNearCommandSubject({
        nearAccountId,
        walletSession: args.walletSession,
      });
      if (!walletIframe.shouldUseWalletIframe()) {
        return await sendTransaction({
          context: getContext(),
          nearAccountId,
          walletSession: commandSubject.walletSession,
          signedTransaction: args.signedTransaction,
          options: args.options,
        });
      }
      try {
        const router = await walletIframe.requireRouter(commandSubject.walletSession.walletId);
        const result = await router.sendTransaction({
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          signedTransaction: args.signedTransaction,
          options: {
            onEvent: args.options?.onEvent,
            ...(args.options && 'waitUntil' in args.options
              ? { waitUntil: args.options.waitUntil }
              : {}),
          },
        });
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    signDelegateAction: async (rawArgs) => {
      // `walletSession`/`nearAccount` are optional on the public surface: omitted,
      // they resolve to the authenticated wallet. `options` normalizes to `{}` so
      // every hook site below can stay unconditional.
      const args = {
        ...rawArgs,
        ...(await deps.currentWallet.nearSubject(rawArgs)),
        options: rawArgs.options ?? {},
      };
      requireNearSigningCapability(
        deps.configs,
        NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction,
      );
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const commandSubject = resolveNearCommandSubject({
        nearAccountId,
        walletSession: args.walletSession,
      });
      const { delegate, options } = args;
      if (!walletIframe.shouldUseWalletIframe()) {
        return await signDelegateActionCore({
          context: getContext(),
          nearAccountId,
          walletSession: commandSubject.walletSession,
          delegate,
          options,
        });
      }
      try {
        const router = await walletIframe.requireRouter(commandSubject.walletSession.walletId);
        const result = await router.signDelegateAction({
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          delegate,
          options: {
            signerSlot: options.signerSlot,
            onEvent: options.onEvent,
            confirmationConfig: options.confirmationConfig,
            confirmerText: options.confirmerText,
          },
        });
        await options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
    sendDelegateActionViaRelayer: async (args) => {
      const base = args.relayerUrl.replace(/\/+$/, '');
      const route = (
        deps.configs.network.relayer?.routes?.delegateAction || '/signed-delegate'
      ).replace(/^\/?/, '/');
      return await sendDelegateActionViaRelayerCore({
        url: `${base}${route}`,
        payload: {
          hash: args.hash,
          signedDelegate: args.signedDelegate,
        },
        auth: delegateRelayerAuthFromConfigs(deps.configs),
        signal: args.signal,
        options: args.options,
      });
    },
    signAndSendDelegateAction: async (rawArgs) => {
      // `walletSession`/`nearAccount` are optional on the public surface: omitted,
      // they resolve to the authenticated wallet. `options` normalizes to `{}` so
      // every hook site below can stay unconditional.
      const args = {
        ...rawArgs,
        ...(await deps.currentWallet.nearSubject(rawArgs)),
        options: rawArgs.options ?? {},
      };
      const signOptions = {
        signerSlot: args.options.signerSlot,
        onEvent: args.options.onEvent,
        onError: args.options.onError,
        waitUntil: args.options.waitUntil,
        confirmationConfig: args.options.confirmationConfig,
        confirmerText: args.options.confirmerText,
        afterCall: () => {},
      };

      let signResult;
      try {
        signResult = await nearCapability.signDelegateAction({
          walletSession: args.walletSession,
          nearAccount: args.nearAccount,
          delegate: args.delegate,
          options: signOptions,
        });
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }

      const relayOptions = {
        onEvent: args.options.onEvent,
        onError: args.options.onError,
      };

      let relayResult;
      try {
        relayResult = await nearCapability.sendDelegateActionViaRelayer({
          relayerUrl: args.relayerUrl,
          hash: signResult.hash,
          signedDelegate: signResult.signedDelegate,
          signal: args.signal,
          options: relayOptions,
        });
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }

      const combined = {
        signResult,
        relayResult,
      };
      if (relayResult.ok !== false) {
        await args.options?.afterCall?.(true, combined);
      } else {
        const relayError = toError(relayResult.error || 'Delegate relay failed');
        await args.options?.afterCall?.(false, undefined, relayError);
      }
      return combined;
    },
    signNEP413Message: async (rawArgs) => {
      // `walletSession`/`nearAccount` are optional on the public surface: omitted,
      // they resolve to the authenticated wallet. `options` normalizes to `{}` so
      // every hook site below can stay unconditional.
      const args = {
        ...rawArgs,
        ...(await deps.currentWallet.nearSubject(rawArgs)),
        options: rawArgs.options ?? {},
      };
      requireNearSigningCapability(
        deps.configs,
        NEAR_ED25519_MPC_OPERATION_KINDS.signNep413Message,
      );
      const walletIframe = deps.getWalletIframe();
      const nearAccountId = args.nearAccount.accountId;
      const commandSubject = resolveNearCommandSubject({
        nearAccountId,
        walletSession: args.walletSession,
      });
      if (!walletIframe.shouldUseWalletIframe()) {
        const result = await signNEP413MessageCore({
          context: getContext(),
          nearAccountId,
          walletSession: commandSubject.walletSession,
          params: args.params,
          options: args.options,
        });
        if (result?.success) {
          await args.options?.afterCall?.(true, result);
        } else {
          const signingError = toError(result?.error || 'NEP-413 signing failed');
          await args.options?.afterCall?.(false, undefined, signingError);
        }
        return result;
      }
      try {
        const router = await walletIframe.requireRouter(commandSubject.walletSession.walletId);
        const result = await router.signNep413Message({
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          message: args.params.message,
          recipient: args.params.recipient,
          state: args.params.state,
          options: {
            signerSlot: args.options.signerSlot,
            onEvent: args.options.onEvent,
            confirmerText: args.options.confirmerText,
            confirmationConfig: args.options.confirmationConfig,
          },
        });
        await args.options?.afterCall?.(true, result);
        return result;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false, undefined, e);
        throw e;
      }
    },
  };
  return nearCapability;
}
