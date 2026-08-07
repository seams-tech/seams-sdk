import { secureRandomId } from '@shared/utils/secureRandomId';
import type { WalletCustodyCeremonyCommitPayload } from '@shared/passkey-custody';
import type { WalletCustodyCeremonyWorkerOperationMap } from '../workerManager/workerTypes';

/**
 * Drives one wallet custody registration ceremony across its three worker
 * steps.
 *
 * The ceremony's state lives in the worker between steps, so an abandoned
 * ceremony holds a seed until the worker is torn down. This driver is what
 * makes abandonment impossible from a call site: every exit path that is not a
 * completed seal discards the ceremony, including the one where the caller's
 * own Router round-trip throws.
 *
 * It does not talk to the relayer itself. The caller supplies `runRouterRound`,
 * which receives the public protocol messages the ceremony produced and returns
 * the terminal results — so the network shape stays with the registration flow
 * that owns it, and this stays testable without one.
 */

type CeremonyOperationMap = WalletCustodyCeremonyWorkerOperationMap;

/** Invokes one worker operation. Supplied by the caller so tests need no worker. */
export type WalletCustodyCeremonyStepRunner = <T extends keyof CeremonyOperationMap>(
  type: T,
  payload: CeremonyOperationMap[T]['payload'],
) => Promise<CeremonyOperationMap[T]['result']>;

/** The public protocol messages the ceremony produced for the Router round. */
export type WalletCustodyCeremonyRouterRequest = {
  readonly yaoExecuteRequestJson: string;
  readonly ecdsaContextBinding32B64u: string;
  readonly ecdsaClientSharePublicKey33B64u: string;
};

/** What the Router and relayer returned, plus the identities to record. */
export type WalletCustodyCeremonyRouterResponse = {
  readonly yaoResultJson: string;
  readonly relayerPublicIdentityJson: string;
  /** `{ nearEd25519SigningKeyId, evmFamilySigningKeySlotId }`. */
  readonly identitiesJson: string;
};

export type WalletCustodyRegistrationCeremonyInput = {
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly walletId: string;
  /** `RegistrationProtocolInputsWireV1`; no Ed25519 binding digest field. */
  readonly protocolInputsJson: string;
  readonly runRouterRound: (
    request: WalletCustodyCeremonyRouterRequest,
  ) => Promise<WalletCustodyCeremonyRouterResponse>;
  readonly factorJson: string;
  /**
   * The factor secret whose KEK seals the envelope. The caller keeps ownership:
   * this driver hands it to the worker and does not retain it.
   */
  readonly factorSecret: ArrayBuffer;
  readonly recoveryCodesJson: string;
  /** Overridable so tests are deterministic; production takes the default. */
  readonly ceremonyId?: string;
};

export async function runWalletCustodyRegistrationCeremony(
  input: WalletCustodyRegistrationCeremonyInput,
): Promise<WalletCustodyCeremonyCommitPayload> {
  const ceremonyId =
    input.ceremonyId ||
    secureRandomId('wallet-custody-ceremony', 32, 'wallet custody ceremony IDs');

  const begun = await input.runStep('beginWalletCustodyRegistration', {
    ceremonyId,
    walletId: input.walletId,
    protocolInputsJson: input.protocolInputsJson,
  });

  try {
    const round = await input.runRouterRound({
      yaoExecuteRequestJson: begun.yaoExecuteRequestJson,
      ecdsaContextBinding32B64u: begun.ecdsaContextBinding32B64u,
      ecdsaClientSharePublicKey33B64u: begun.ecdsaClientSharePublicKey33B64u,
    });

    await input.runStep('completeWalletCustodyRegistration', {
      ceremonyId,
      yaoResultJson: round.yaoResultJson,
      relayerPublicIdentityJson: round.relayerPublicIdentityJson,
      identitiesJson: round.identitiesJson,
    });

    return await input.runStep('sealWalletCustodyRegistration', {
      ceremonyId,
      factorJson: input.factorJson,
      factorSecret: input.factorSecret,
      recoveryCodesJson: input.recoveryCodesJson,
    });
  } catch (error: unknown) {
    // The worker already dropped the handle for a step that threw inside it,
    // but a Router round that failed leaves a live ceremony holding a seed.
    // Discarding covers both, and must not mask the original failure.
    await input.runStep('discardWalletCustodyCeremony', { ceremonyId }).catch(() => undefined);
    throw error;
  }
}
