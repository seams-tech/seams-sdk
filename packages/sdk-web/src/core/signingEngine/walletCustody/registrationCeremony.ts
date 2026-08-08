import { base64UrlEncode } from '@shared/utils/encoders';
import {
  issueWalletRecoveryCodes,
  zeroizeIssuedWalletRecoveryCodes,
  type IssuedWalletRecoveryCodes,
} from '@shared/wallet-recovery/recoveryCodes';
import type { WalletCustodyCeremonyCommitPayload } from '@shared/passkey-custody';
import {
  runWalletCustodyKeySetCeremony,
  type WalletCustodyCeremonyStepRunner,
} from './ceremonyDriver';

/**
 * One NEAR Ed25519 key set provisioned from the wallet custody seed.
 *
 * This is the establishing half of the registration splice: it issues the
 * recovery set, runs the ceremony, and returns both the codes to show the user
 * and the payload to commit. The two are returned together because they are
 * produced together and are useless apart — the wraps are one-way, so codes
 * that are not shown are codes nobody can ever produce, and a payload committed
 * without its codes leaves a wallet whose owner holds nothing.
 */

export type EstablishNearEd25519CustodyInput = {
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly walletId: string;
  /** The passkey or Email OTP factor, as the envelope will name it. */
  readonly factorJson: string;
  /** `PRF.first` or the Email OTP factor key. Owned by the caller. */
  readonly factorSecret: ArrayBuffer;
  readonly nearEd25519SigningKeyId: string;
  /** The Yao lifecycle this run registers under, and route 4's own scope. */
  readonly registrationCeremonyId: string;
  /** The Yao admission receipt and application facts this run registers under. */
  readonly yaoAdmission: unknown;
  readonly yaoApplication: unknown;
  readonly participantIds: readonly [number, number];
  /** Takes the Router execution request, returns the activation result. */
  readonly runRouterRound: (yaoExecuteRequestJson: string) => Promise<string>;
  /** Present when this key set already has a registration to reproduce. */
  readonly continuityRegisteredPublicKeyB64u?: string;
};

export type EstablishedNearEd25519Custody = {
  /** Show these once. They are the only copy. */
  readonly recoveryCodes: readonly string[];
  /** Ready for the wire: carries no client signing material. */
  readonly commitPayload: WalletCustodyCeremonyCommitPayload;
  /**
   * The same-device continuity cache, kept on the client.
   *
   * Deliberately separate from `commitPayload` rather than a field the caller
   * must remember to strip: the type makes it impossible to send by accident.
   */
  readonly localMaterial: { readonly b64u: string; readonly nonceB64u: string } | null;
  /**
   * The one-use reference the deferred NEAR provisioning leg claims this run's
   * Yao result with.
   *
   * Returned from here because this run owns the Router round and nothing else
   * sees its result. The PRF-derived path read the equivalent off the active
   * client it kept; a ceremony keeps no client, so the reference has to come
   * out with the payload or the leg has nothing to present.
   */
  readonly activationReference: {
    readonly kind: 'router_ab_ed25519_yao_activation_reference_v1';
    readonly lifecycle_id: string;
    readonly session_id: readonly number[];
  };
};

export async function establishNearEd25519CustodyV1(
  input: EstablishNearEd25519CustodyInput,
): Promise<EstablishedNearEd25519Custody> {
  let issued: IssuedWalletRecoveryCodes | null = issueWalletRecoveryCodes();
  let activationSessionId: readonly number[] | null = null;
  try {
    const payload = await runWalletCustodyKeySetCeremony({
      runStep: input.runStep,
      custody: {
        origin: 'establish',
        walletId: input.walletId,
        factorJson: input.factorJson,
        factorSecret: input.factorSecret,
        /* Bytes only. The ceremony derives each code's id from the wallet and
           these bytes as it seals, so no id crosses the boundary and the
           sealer and a later reader cannot disagree about what an id is. */
        recoveryCodesJson: JSON.stringify(
          issued.codeBytes.map((bytes) => ({ codeBytesB64u: base64UrlEncode(bytes) })),
        ),
      },
      keySetRun: {
        keySet: 'near_ed25519_v1',
        protocolInputsJson: JSON.stringify({
          yaoAdmission: input.yaoAdmission,
          yaoApplication: input.yaoApplication,
          clientParticipantId: input.participantIds[0],
          signingWorkerParticipantId: input.participantIds[1],
          ...(input.continuityRegisteredPublicKeyB64u === undefined
            ? {}
            : {
                continuityRegisteredPublicKeyB64u: input.continuityRegisteredPublicKeyB64u,
              }),
        }),
        nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
        /* Wrapped so this run keeps the activation session id. The ceremony
           consumes the Router's result and returns only public facts, so a
           caller that let the round pass through untouched would have no way
           to claim the result on the deferred leg. */
        runRouterRound: async (yaoExecuteRequestJson: string) => {
          const resultJson = await input.runRouterRound(yaoExecuteRequestJson);
          activationSessionId = activationSessionIdFromResult(resultJson);
          return resultJson;
        },
      },
    });

    if (!activationSessionId) {
      throw new Error('the NEAR custody ceremony produced no activation session id');
    }

    return {
      recoveryCodes: issued.codes,
      activationReference: {
        kind: 'router_ab_ed25519_yao_activation_reference_v1',
        // The lifecycle is the ceremony's own: the Yao lifecycle id is minted
        // from the registration ceremony id, and finalize refuses a reference
        // naming another.
        lifecycle_id: input.registrationCeremonyId,
        session_id: activationSessionId,
      },
      commitPayload: walletCustodyCommitPayloadForWire(payload),
      localMaterial:
        payload.ed25519LocalMaterialB64u && payload.ed25519LocalMaterialNonceB64u
          ? {
              b64u: payload.ed25519LocalMaterialB64u,
              nonceB64u: payload.ed25519LocalMaterialNonceB64u,
            }
          : null,
    };
  } finally {
    if (issued) zeroizeIssuedWalletRecoveryCodes(issued);
    issued = null;
  }
}

/**
 * Strips everything the server must never receive.
 *
 * The Gateway drops these too, so this is the second of two independent
 * guards — but only this one keeps them off the wire at all. The ECDSA
 * ready-state blob is the sharper case of the two: it is not self-encrypted,
 * and the client's signing share falls out of its bytes with no key, so
 * sending it would hand one share of a 2-of-2 key to the holder of the other.
 * The Ed25519 cache is a same-device record the server has no use for.
 */
export function walletCustodyCommitPayloadForWire(
  payload: WalletCustodyCeremonyCommitPayload,
): WalletCustodyCeremonyCommitPayload {
  const {
    ed25519LocalMaterialB64u: _cache,
    ed25519LocalMaterialNonceB64u: _cacheNonce,
    ecdsaReadyStateBlobB64u: _readyState,
    ...wire
  } = payload;
  return wire;
}

/**
 * Reads the activation session id out of the Router's result.
 *
 * Parsed rather than accepted as a separate argument so it can only be the id
 * of the round this run actually performed — a caller-supplied one could name
 * another ceremony's activation, which the finalize leg would then burn.
 */
function activationSessionIdFromResult(resultJson: string): readonly number[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(resultJson);
  } catch {
    throw new Error('the Router activation result is not JSON');
  }
  const binding = (parsed as { binding?: { session_id?: unknown } } | null)?.binding;
  const sessionId = binding?.session_id;
  if (!Array.isArray(sessionId) || sessionId.length === 0) {
    throw new Error('the Router activation result carries no session id');
  }
  return sessionId.map((byte) => {
    if (typeof byte !== 'number' || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new Error('the Router activation session id is not a byte array');
    }
    return byte;
  });
}
