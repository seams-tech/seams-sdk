import {
  nearAccountRefFromAccountId,
  walletSessionRefFromSession,
  type NearAccountRef,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletSession } from '@/core/types/seams';

/** A NEAR account named exactly, or by its account id. */
export type NearAccountInput = NearAccountRef | string;

/**
 * A wallet named exactly, or by its wallet id.
 *
 * `WalletSessionRef` also carries a wallet-scoped audit subject that defaults to
 * the wallet id, so an application never has to construct one: passing the id is
 * equivalent and reads better.
 */
export type WalletSessionInput = WalletSessionRef | string;

/**
 * Fills in the wallet a call authorizes when the caller did not name one.
 *
 * The default is always the **authenticated** wallet — `session.authentication`
 * — never the `preferences.setCurrentWallet` mirror, which is a public
 * unauthenticated setter and in iframe mode is only a parent-page value. An
 * explicit `walletSession` always wins, so the exact-reference API stays intact
 * for callers that manage several wallets.
 */
export interface CurrentWalletResolver {
  walletSession(explicit?: WalletSessionInput): Promise<WalletSessionRef>;
  nearSubject(explicit: {
    walletSession?: WalletSessionInput;
    nearAccount?: NearAccountInput;
  }): Promise<{ walletSession: WalletSessionRef; nearAccount: NearAccountRef }>;
}

function toWalletSessionRef(input: WalletSessionInput): WalletSessionRef {
  return typeof input === 'string' ? walletSessionRefFromSession({ walletId: input }) : input;
}

function toNearAccountRef(input: NearAccountInput): NearAccountRef {
  return typeof input === 'string' ? nearAccountRefFromAccountId(input) : input;
}

export function createCurrentWalletResolver(deps: {
  getWalletSession: (walletId?: string) => Promise<WalletSession>;
}): CurrentWalletResolver {
  const readAuthenticatedSession = async (): Promise<WalletSession> => {
    const session = await deps.getWalletSession();
    if (session.authentication.kind !== 'authenticated') {
      throw new Error(
        '[seams] no authenticated wallet: unlock a wallet first, or pass an explicit `walletSession`.',
      );
    }
    return session;
  };

  const walletSession = async (explicit?: WalletSessionInput): Promise<WalletSessionRef> => {
    if (explicit) return toWalletSessionRef(explicit);
    const session = await readAuthenticatedSession();
    return walletSessionRefFromSession({ walletId: session.authentication.walletId });
  };

  return {
    walletSession,
    nearSubject: async (explicit) => {
      if (explicit.walletSession && explicit.nearAccount) {
        return {
          walletSession: toWalletSessionRef(explicit.walletSession),
          nearAccount: toNearAccountRef(explicit.nearAccount),
        };
      }
      const session = await readAuthenticatedSession();
      const authenticatedWalletId = session.authentication.walletId;
      const resolvedSession = explicit.walletSession
        ? toWalletSessionRef(explicit.walletSession)
        : walletSessionRefFromSession({ walletId: authenticatedWalletId });
      if (explicit.nearAccount) {
        return {
          walletSession: resolvedSession,
          nearAccount: toNearAccountRef(explicit.nearAccount),
        };
      }
      // `appIdentity` resolves for wallets the user is not signed into, so only
      // trust it when it names the same wallet the session authenticated.
      const identity = session.appIdentity;
      if (
        identity.kind !== 'resolved' ||
        String(identity.walletId) !== String(authenticatedWalletId)
      ) {
        throw new Error(
          '[seams] the authenticated wallet has no resolved NEAR account: pass an explicit `nearAccount`.',
        );
      }
      if (!identity.nearAccountId) {
        throw new Error(
          '[seams] this wallet has no NEAR account yet (NEAR provisioning may still be pending): pass an explicit `nearAccount`, or await `seams.registration.awaitNearReady`.',
        );
      }
      return {
        walletSession: resolvedSession,
        nearAccount: nearAccountRefFromAccountId(identity.nearAccountId),
      };
    },
  };
}
