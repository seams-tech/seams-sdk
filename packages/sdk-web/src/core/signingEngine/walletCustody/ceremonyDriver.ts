import { secureRandomId } from '@shared/utils/secureRandomId';
import type { WalletCustodyCeremonyCommitPayload } from '@shared/passkey-custody';
import type { WalletCustodyCeremonyWorkerOperationMap } from '../workerManager/workerTypes';

/**
 * Drives one wallet custody ceremony run across its three worker steps.
 *
 * A run provisions one key set. It either establishes custody — the wallet's
 * first key set, where the seed is generated, sealed under a factor, and
 * covered by a fresh recovery set — or joins custody that already exists,
 * reaching the same seed by opening its envelope and writing nothing but its
 * own manifest.
 *
 * That choice is a discriminated union rather than a flag plus optional fields,
 * so the two combinations the ceremony refuses at runtime cannot be written
 * here at all: an establishing run always carries what sealing needs, and a
 * joining run has nowhere to put it. Getting it wrong would give the wallet a
 * second seed and a second recovery set, leaving half its keys covered by
 * neither.
 *
 * The run's state lives in the worker between steps, so an abandoned run holds
 * a seed until the worker is torn down. This driver is what makes abandonment
 * impossible from a call site: every exit path that is not a completed finish
 * discards the run, including the one where the caller's own protocol
 * round-trip throws.
 *
 * It does not talk to the Router or the relayer itself. The caller supplies the
 * round, which receives the public protocol messages the run produced and
 * returns the terminal result — so the network shape stays with the
 * registration flow that owns it, and this stays testable without one.
 */

type CeremonyOperationMap = WalletCustodyCeremonyWorkerOperationMap;
type BegunRun = CeremonyOperationMap['beginWalletCustodyKeySetRun']['result'];
type CompletedRun = CeremonyOperationMap['completeWalletCustodyKeySetRun']['result'];

/** Invokes one worker operation. Supplied by the caller so tests need no worker. */
export type WalletCustodyCeremonyStepRunner = <T extends keyof CeremonyOperationMap>(
  type: T,
  payload: CeremonyOperationMap[T]['payload'],
) => Promise<CeremonyOperationMap[T]['result']>;

/**
 * Where this run's seed comes from, and what that obliges it to do at the end.
 *
 * Both origins carry a factor secret, for opposite reasons: an establishing run
 * seals the seed under it, a joining run opens the existing envelope with it.
 * The caller keeps ownership either way — this driver hands it to the worker
 * and does not retain it.
 */
export type WalletCustodyCeremonyCustodyInput =
  | {
      readonly origin: 'establish';
      readonly walletId: string;
      readonly factorJson: string;
      readonly factorSecret: ArrayBuffer;
      readonly recoveryCodesJson: string;
    }
  | {
      readonly origin: 'join';
      /** `JoinCustodyWireV1`: the envelope binding and its sealed seed. */
      readonly custodyJson: string;
      readonly factorSecret: ArrayBuffer;
    }
  | {
      readonly origin: 'recover';
      /** `RecoveryCustodyWireV1`: one reserved wrap and the wallet seed entry. */
      readonly custodyJson: string;
      readonly recoveryCode: ArrayBuffer;
    };

/**
 * The key set this run provisions, its protocol inputs, and the counterparty
 * that returns the terminal result.
 *
 * A NEAR Ed25519 run's counterparty is the Router; an EVM-family run's is the
 * relayer. They are separate members because the two rounds carry different
 * messages, and because the identity each key set records is a different field.
 */
export type WalletCustodyCeremonyKeySetInput =
  | {
      readonly keySet: 'near_ed25519_v1';
      /** `NearEd25519ProtocolInputsWireV1`; no Ed25519 binding digest field. */
      readonly protocolInputsJson: string;
      readonly nearEd25519SigningKeyId: string;
      /** Takes the Router execution request, returns the activation result. */
      readonly runRouterRound: (yaoExecuteRequestJson: string) => Promise<string>;
    }
  | {
      readonly keySet: 'evm_family_ecdsa_v1';
      /** `EvmFamilyProtocolInputsWireV1`. */
      readonly protocolInputsJson: string;
      readonly evmFamilySigningKeySlotId: string;
      /** Local backup gate. Runs after the opaque commit exists, before network activation. */
      readonly beforeRelayerRound: () => Promise<void>;
      /** Takes the client's bootstrap facts, returns the relayer public identity. */
      readonly runRelayerRound: (bootstrap: {
        readonly contextBinding32B64u: string;
        readonly clientSharePublicKey33B64u: string;
        readonly clientShareRetryCounter: number;
        readonly preActivationCommitPayload: WalletCustodyCeremonyCommitPayload;
      }) => Promise<string>;
    };

export type WalletCustodyKeySetCeremonyInput = {
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly custody: WalletCustodyCeremonyCustodyInput;
  readonly keySetRun: WalletCustodyCeremonyKeySetInput;
  /**
   * The digest already riding this key set's registration state, when it has
   * one. Present means the run must reproduce it — which is what stops an
   * induced re-run from silently replacing a key set.
   */
  readonly recordedKeyManifestDigestB64u?: string;
  /** Overridable so tests are deterministic; production takes the default. */
  readonly ceremonyId?: string;
};

function ignoreDiscardFailure(): void {
  return;
}

function requireNearBegunRun(
  begun: BegunRun,
): Extract<BegunRun, { readonly keySet: 'near_ed25519_v1' }> {
  if (begun.keySet !== 'near_ed25519_v1') {
    throw new Error('The custody worker began an EVM run for a NEAR request');
  }
  return begun;
}

function requireEvmBegunRun(
  begun: BegunRun,
): Extract<BegunRun, { readonly keySet: 'evm_family_ecdsa_v1' }> {
  if (begun.keySet !== 'evm_family_ecdsa_v1') {
    throw new Error('The custody worker began a NEAR run for an EVM request');
  }
  return begun;
}

function requireEvmCompletedRun(
  completed: CompletedRun,
): Extract<CompletedRun, { readonly keySet: 'evm_family_ecdsa_v1' }> {
  if (completed.keySet !== 'evm_family_ecdsa_v1') {
    throw new Error('The custody worker completed a NEAR run for an EVM request');
  }
  return completed;
}

type NearBeginCustody = Extract<
  CeremonyOperationMap['beginWalletCustodyKeySetRun']['payload'],
  { readonly keySet: 'near_ed25519_v1' }
>['custody'];

function buildNearBeginCustody(custody: WalletCustodyCeremonyCustodyInput): NearBeginCustody {
  switch (custody.origin) {
    case 'establish':
      return { origin: 'establish', walletId: custody.walletId };
    case 'join':
      return {
        origin: 'join',
        custodyJson: custody.custodyJson,
        factorSecret: custody.factorSecret,
      };
    case 'recover':
      return {
        origin: 'recover',
        custodyJson: custody.custodyJson,
        recoveryCode: custody.recoveryCode,
      };
    default:
      return assertNeverCustodyOrigin(custody);
  }
}

function assertNeverCustodyOrigin(value: never): never {
  throw new Error(`Unsupported wallet custody origin: ${String(value)}`);
}

function assertEvmCompletionMatchesCommit(
  preActivation: WalletCustodyCeremonyCommitPayload,
  completion: Extract<CompletedRun, { readonly keySet: 'evm_family_ecdsa_v1' }>,
): void {
  if (preActivation.walletId !== completion.activation.walletId) {
    throw new Error('EVM custody activation changed the wallet identity');
  }
  if (preActivation.keyManifestDigestB64u !== completion.activation.keyManifestDigestB64u) {
    throw new Error('EVM custody activation changed the key manifest digest');
  }
  if (preActivation.clientRootPublicKey33B64u !== completion.activation.clientRootPublicKey33B64u) {
    throw new Error('EVM custody activation changed the client root public key');
  }
}

export async function runWalletCustodyKeySetCeremony(
  input: WalletCustodyKeySetCeremonyInput,
): Promise<WalletCustodyCeremonyCommitPayload> {
  const ceremonyId =
    input.ceremonyId ||
    secureRandomId('wallet-custody-ceremony', 32, 'wallet custody ceremony IDs');
  const { custody, keySetRun } = input;
  let workerAcceptedBegin = false;

  try {
    if (keySetRun.keySet === 'near_ed25519_v1') {
      const begunResult = await input.runStep('beginWalletCustodyKeySetRun', {
        ceremonyId,
        keySet: 'near_ed25519_v1',
        custody: buildNearBeginCustody(custody),
        protocolInputsJson: keySetRun.protocolInputsJson,
      });
      workerAcceptedBegin = true;
      const begun = requireNearBegunRun(begunResult);
      const protocolResultJson = await keySetRun.runRouterRound(begun.yaoExecuteRequestJson);
      await input.runStep('completeWalletCustodyKeySetRun', {
        ceremonyId,
        keySet: 'near_ed25519_v1',
        protocolResultJson,
        nearEd25519SigningKeyId: keySetRun.nearEd25519SigningKeyId,
        recordedKeyManifestDigestB64u: input.recordedKeyManifestDigestB64u,
      });
      return await input.runStep('finishWalletCustodyKeySetRun', {
        ceremonyId,
        establishWith:
          custody.origin === 'establish'
            ? {
                factorJson: custody.factorJson,
                factorSecret: custody.factorSecret,
                recoveryCodesJson: custody.recoveryCodesJson,
              }
            : undefined,
      });
    }

    const begunResult = await input.runStep('beginWalletCustodyKeySetRun', {
      ceremonyId,
      keySet: 'evm_family_ecdsa_v1',
      custody,
      protocolInputsJson: keySetRun.protocolInputsJson,
      evmFamilySigningKeySlotId: keySetRun.evmFamilySigningKeySlotId,
      recordedKeyManifestDigestB64u: input.recordedKeyManifestDigestB64u,
    });
    workerAcceptedBegin = true;
    const begun = requireEvmBegunRun(begunResult);
    await keySetRun.beforeRelayerRound();
    const protocolResultJson = await keySetRun.runRelayerRound({
      contextBinding32B64u: begun.ecdsaContextBinding32B64u,
      clientSharePublicKey33B64u: begun.ecdsaClientSharePublicKey33B64u,
      clientShareRetryCounter: begun.ecdsaClientShareRetryCounter,
      preActivationCommitPayload: begun.preActivationCommitPayload,
    });
    const completed = requireEvmCompletedRun(
      await input.runStep('completeWalletCustodyKeySetRun', {
        ceremonyId,
        keySet: 'evm_family_ecdsa_v1',
        protocolResultJson,
      }),
    );
    assertEvmCompletionMatchesCommit(begun.preActivationCommitPayload, completed);
    return {
      ...begun.preActivationCommitPayload,
      clientRootPublicKey33B64u: completed.activation.clientRootPublicKey33B64u,
      ecdsaReadyStateBlobB64u: completed.activation.ecdsaReadyStateBlobB64u,
      ecdsaPublicFacts: completed.activation.ecdsaPublicFacts,
    };
  } catch (error: unknown) {
    // The worker already dropped the handle for a step that threw inside it,
    // but a protocol round that failed leaves a live run holding a seed.
    // Discarding covers both, and must not mask the original failure.
    if (workerAcceptedBegin) {
      await input
        .runStep('discardWalletCustodyCeremony', { ceremonyId })
        .catch(ignoreDiscardFailure);
    }
    throw error;
  }
}
