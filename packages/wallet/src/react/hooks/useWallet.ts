import { useMemo } from 'react';
import { useSeams } from '../context';
import {
  nearAccountRefFromAccountId,
  walletSessionRefFromSession,
  type NearAccountRef,
  type WalletSessionRef,
} from '../../boundary/walletRefs';
import type { SeamsWeb } from '../../SeamsWeb';
import type {
  ExportKeypairInput,
  KeyExportOutcome,
  NearSignerCapability,
  TempoSignerCapability,
} from '../../SeamsWeb/publicApi/types';

// Distributive, so unions (EVM vs Tempo requests, Ed25519 vs ECDSA export)
// keep their arms paired instead of collapsing into one loose object.
type WithoutNearSubject<T> = T extends unknown ? Omit<T, 'walletSession' | 'nearAccount'> : never;
type WithoutWalletSession<T> = T extends unknown ? Omit<T, 'walletSession'> : never;

/** NEAR signing bound to one wallet and account: the call names only the transaction. */
export interface BoundNearSigner {
  readonly accountId: string;
  signAndSendTransaction(
    args: WithoutNearSubject<Parameters<NearSignerCapability['signAndSendTransaction']>[0]>,
  ): ReturnType<NearSignerCapability['signAndSendTransaction']>;
  executeAction(
    args: WithoutNearSubject<Parameters<NearSignerCapability['executeAction']>[0]>,
  ): ReturnType<NearSignerCapability['executeAction']>;
  signNEP413Message(
    args: WithoutNearSubject<Parameters<NearSignerCapability['signNEP413Message']>[0]>,
  ): ReturnType<NearSignerCapability['signNEP413Message']>;
}

/** EVM-family signing bound to one wallet. */
export interface BoundEvmSigner {
  execute(
    args: WithoutWalletSession<Parameters<TempoSignerCapability['executeEvmFamilyTransaction']>[0]>,
  ): ReturnType<TempoSignerCapability['executeEvmFamilyTransaction']>;
  signTransaction(
    args: WithoutWalletSession<Parameters<TempoSignerCapability['signTempo']>[0]>,
  ): ReturnType<TempoSignerCapability['signTempo']>;
}

export interface BoundWallet {
  readonly walletId: string;
  /** The exact reference every bound call authorizes. */
  readonly walletSession: WalletSessionRef;
  /**
   * NEAR signing, or `null` when this wallet has no NEAR account — it is
   * EVM-only, or provisioning has not finished. Wait for one with
   * `seams.registration.awaitNearReady({ walletId })`.
   */
  readonly near: BoundNearSigner | null;
  readonly evm: BoundEvmSigner;
  exportKey(input: WithoutNearSubject<ExportKeypairInput>): Promise<KeyExportOutcome>;
}

export type UseWalletResult =
  | { status: 'signed_out'; wallet: null; walletId: null; nearAccountId: null }
  | {
      status: 'ready';
      wallet: BoundWallet;
      walletId: string;
      /** `null` when the wallet has no NEAR account. */
      nearAccountId: string | null;
    };

function createBoundWallet(
  seams: SeamsWeb,
  walletId: string,
  nearAccountId: string | null,
): BoundWallet {
  const walletSession = walletSessionRefFromSession({ walletId });
  const nearAccount: NearAccountRef | null = nearAccountId
    ? nearAccountRefFromAccountId(nearAccountId)
    : null;

  // Bind the wallet the UI rendered, rather than re-resolving per call: a
  // button signs with the wallet the person was looking at when they clicked.
  const near: BoundNearSigner | null =
    nearAccount && nearAccountId
      ? {
          accountId: nearAccountId,
          signAndSendTransaction: (args) =>
            seams.near.signAndSendTransaction({ ...args, walletSession, nearAccount }),
          executeAction: (args) =>
            seams.near.executeAction({ ...args, walletSession, nearAccount }),
          signNEP413Message: (args) =>
            seams.near.signNEP413Message({ ...args, walletSession, nearAccount }),
        }
      : null;

  return {
    walletId,
    walletSession,
    near,
    evm: {
      execute: (args) => seams.tempo.executeEvmFamilyTransaction({ ...args, walletSession }),
      signTransaction: (args) => seams.tempo.signTempo({ ...args, walletSession }),
    },
    exportKey: async (input) => {
      if (input.kind === 'ed25519') {
        return await seams.keys.exportKeypair({
          ...input,
          walletSession,
          ...(nearAccount ? { nearAccount } : {}),
        });
      }
      return await seams.keys.exportKeypair({ ...input, walletSession });
    },
  };
}

/**
 * The signed-in wallet, with signing bound to it.
 *
 * `useSeams()` gives you the whole client; `useWallet()` gives you the one
 * wallet the person is signed into, so a signing call names only the
 * transaction. Reach for `useSeams().seams` when you need to target a different
 * wallet explicitly.
 *
 * Two things can be absent, and both are worth a real check rather than an
 * optional chain: `wallet` is null when nobody is signed in, and `near` is null
 * when the signed-in wallet has no NEAR account. One guard narrows both.
 *
 * @example
 * const { wallet } = useWallet();
 * if (!wallet) return <SignInButton />;
 * if (!wallet.near) return <NearAccountPending />;
 * await wallet.near.signAndSendTransaction({ receiverId, actions });
 */
export function useWallet(): UseWalletResult {
  const { seams, loginState } = useSeams();
  const walletId = loginState.isLoggedIn ? loginState.walletId : null;
  const nearAccountId = loginState.isLoggedIn ? loginState.nearAccountId : null;

  return useMemo<UseWalletResult>(() => {
    if (!walletId) {
      return { status: 'signed_out', wallet: null, walletId: null, nearAccountId: null };
    }
    return {
      status: 'ready',
      wallet: createBoundWallet(seams, walletId, nearAccountId),
      walletId,
      nearAccountId,
    };
  }, [seams, walletId, nearAccountId]);
}
