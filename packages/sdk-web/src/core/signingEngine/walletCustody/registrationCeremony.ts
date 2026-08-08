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
};

export async function establishNearEd25519CustodyV1(
  input: EstablishNearEd25519CustodyInput,
): Promise<EstablishedNearEd25519Custody> {
  let issued: IssuedWalletRecoveryCodes | null = issueWalletRecoveryCodes();
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
        runRouterRound: input.runRouterRound,
      },
    });

    return {
      recoveryCodes: issued.codes,
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
