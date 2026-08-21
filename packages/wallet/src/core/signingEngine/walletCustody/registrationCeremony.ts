import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { sha256Bytes } from '@shared/utils/digests';
import {
  issueWalletRecoveryCodes,
  zeroizeIssuedWalletRecoveryCodes,
  type IssuedWalletRecoveryCodes,
} from '@shared/wallet-recovery/recoveryCodes';
import { deriveRecoveryCodeLocatorV1FromBytes } from '@shared/wallet-recovery/recoveryCodeLocator';
import {
  walletCustodyCommitPayloadWithRecoveryBackupAcknowledgement,
  type WalletCustodyCeremonyCommitPayload,
  type WalletCustodyEvmFamilyPublicFacts,
} from '@shared/passkey-custody';
import type { RouterAbEd25519YaoRecoveryActivationReceiptV1 } from '@shared/utils/routerAbEd25519Yao';
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
  readonly localMaterial: {
    readonly b64u: string;
    readonly nonceB64u: string;
    /** A field of the seal binding, so opening the cache needs it verbatim. */
    readonly applicationBindingDigestB64u: string;
  } | null;
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

    const commitPayload = await walletCustodyCommitPayloadWithRecoveryCodeLocators(payload, issued);
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
      commitPayload: walletCustodyCommitPayloadForWire(commitPayload),
      localMaterial:
        payload.ed25519LocalMaterialB64u &&
        payload.ed25519LocalMaterialNonceB64u &&
        payload.ed25519ApplicationBindingDigestB64u
          ? {
              b64u: payload.ed25519LocalMaterialB64u,
              nonceB64u: payload.ed25519LocalMaterialNonceB64u,
              applicationBindingDigestB64u: payload.ed25519ApplicationBindingDigestB64u,
            }
          : null,
    };
  } finally {
    if (issued) zeroizeIssuedWalletRecoveryCodes(issued);
    issued = null;
  }
}

export type EstablishEvmFamilyCustodyInput = {
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly walletId: string;
  readonly factorJson: string;
  readonly factorSecret: ArrayBuffer;
  readonly evmFamilySigningKeySlotId: string;
  readonly applicationBindingDigestB64u: string;
  /** Must resolve before the activation payload is allowed onto the wire. */
  readonly confirmRecoveryCodesBackedUp: (recoveryCodes: readonly string[]) => Promise<void>;
  readonly runRelayerRound: (bootstrap: {
    readonly contextBinding32B64u: string;
    readonly clientSharePublicKey33B64u: string;
    readonly clientShareRetryCounter: number;
    readonly preActivationCommitPayload: WalletCustodyCeremonyCommitPayload;
  }) => Promise<string>;
};

export type EstablishedEvmFamilyCustody = {
  readonly recoveryCodes: readonly string[];
  /** The exact payload admitted during activation, before local completion. */
  readonly commitPayload: WalletCustodyCeremonyCommitPayload;
  readonly clientBootstrap: {
    readonly contextBinding32B64u: string;
    readonly derivationClientSharePublicKey33B64u: string;
    readonly clientShareRetryCounter: number;
    readonly participantId: 1;
  };
  readonly localMaterial: {
    readonly readyStateBlobB64u: string;
    readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
  };
};

export function joinCustodyJsonFromEstablishedCommitPayload(
  payload: WalletCustodyCeremonyCommitPayload,
): string {
  const established = payload.establishedCustody;
  if (!established) {
    throw new Error('wallet custody join requires an established envelope');
  }
  let envelopeBinding: unknown;
  try {
    envelopeBinding = JSON.parse(established.envelopeBindingJson);
  } catch {
    throw new Error('wallet custody envelope binding is not JSON');
  }
  if (
    typeof envelopeBinding !== 'object' ||
    envelopeBinding === null ||
    Array.isArray(envelopeBinding)
  ) {
    throw new Error('wallet custody envelope binding must be an object');
  }
  return JSON.stringify({
    envelopeBinding,
    nonceB64u: established.envelopeNonceB64u,
    sealedCustodySecretB64u: established.sealedCustodySecretB64u,
    aadHashB64u: established.envelopeAadHashB64u,
    ciphertextDigestB64u: established.envelopeCiphertextDigestB64u,
  });
}

export async function establishEvmFamilyCustodyV1(
  input: EstablishEvmFamilyCustodyInput,
): Promise<EstablishedEvmFamilyCustody> {
  let issued: IssuedWalletRecoveryCodes | null = issueWalletRecoveryCodes();
  let admittedCommitPayload: WalletCustodyCeremonyCommitPayload | null = null;
  let clientBootstrap: EstablishedEvmFamilyCustody['clientBootstrap'] | null = null;
  try {
    const issuedForCeremony = issued;
    if (!issuedForCeremony) throw new Error('recovery codes were not issued');
    const payload = await runWalletCustodyKeySetCeremony({
      runStep: input.runStep,
      custody: {
        origin: 'establish',
        walletId: input.walletId,
        factorJson: input.factorJson,
        factorSecret: input.factorSecret,
        recoveryCodesJson: JSON.stringify(
          issued.codeBytes.map((bytes) => ({ codeBytesB64u: base64UrlEncode(bytes) })),
        ),
      },
      keySetRun: {
        keySet: 'evm_family_ecdsa_v1',
        protocolInputsJson: JSON.stringify({
          applicationBindingDigestB64u: input.applicationBindingDigestB64u,
        }),
        evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
        beforeRelayerRound: input.confirmRecoveryCodesBackedUp.bind(undefined, issued.codes),
        runRelayerRound: async (bootstrap) => {
          const enrichedCommitPayload = await walletCustodyCommitPayloadWithRecoveryCodeLocators(
            bootstrap.preActivationCommitPayload,
            issuedForCeremony,
          );
          const preActivationCommitPayload =
            walletCustodyCommitPayloadWithRecoveryBackupAcknowledgement(enrichedCommitPayload);
          admittedCommitPayload = preActivationCommitPayload;
          clientBootstrap = {
            contextBinding32B64u: bootstrap.contextBinding32B64u,
            derivationClientSharePublicKey33B64u: bootstrap.clientSharePublicKey33B64u,
            clientShareRetryCounter: bootstrap.clientShareRetryCounter,
            participantId: 1,
          };
          return await input.runRelayerRound({ ...bootstrap, preActivationCommitPayload });
        },
      },
    });
    if (!admittedCommitPayload || !clientBootstrap) {
      throw new Error('the EVM custody ceremony reached no activation round');
    }
    if (!payload.ecdsaReadyStateBlobB64u || !payload.ecdsaPublicFacts) {
      throw new Error('the EVM custody ceremony produced no local signing material');
    }
    return {
      recoveryCodes: issued.codes,
      commitPayload: admittedCommitPayload,
      clientBootstrap,
      localMaterial: {
        readyStateBlobB64u: payload.ecdsaReadyStateBlobB64u,
        publicFacts: payload.ecdsaPublicFacts,
      },
    };
  } finally {
    if (issued) zeroizeIssuedWalletRecoveryCodes(issued);
    issued = null;
  }
}

export type RejoinEvmFamilyCustodyInput = {
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly walletId: string;
  readonly custodyJson: string;
  readonly factorSecret: ArrayBuffer;
  readonly evmFamilySigningKeySlotId: string;
  readonly applicationBindingDigestB64u: string;
  readonly registeredClientRootPublicKey33B64u: string;
  readonly relayerPublicIdentityJson: string;
};

export type JoinEvmFamilyCustodyInput = Omit<
  EstablishEvmFamilyCustodyInput,
  'factorJson' | 'confirmRecoveryCodesBackedUp'
> & {
  readonly custodyJson: string;
};

export type JoinedEvmFamilyCustody = Omit<EstablishedEvmFamilyCustody, 'recoveryCodes'>;

export async function joinEvmFamilyCustodyV1(
  input: JoinEvmFamilyCustodyInput,
): Promise<JoinedEvmFamilyCustody> {
  let admittedCommitPayload: WalletCustodyCeremonyCommitPayload | null = null;
  let clientBootstrap: EstablishedEvmFamilyCustody['clientBootstrap'] | null = null;
  const payload = await runWalletCustodyKeySetCeremony({
    runStep: input.runStep,
    custody: {
      origin: 'join',
      custodyJson: input.custodyJson,
      factorSecret: input.factorSecret,
    },
    keySetRun: {
      keySet: 'evm_family_ecdsa_v1',
      protocolInputsJson: JSON.stringify({
        applicationBindingDigestB64u: input.applicationBindingDigestB64u,
      }),
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      beforeRelayerRound: async () => undefined,
      runRelayerRound: async (bootstrap) => {
        admittedCommitPayload = bootstrap.preActivationCommitPayload;
        clientBootstrap = {
          contextBinding32B64u: bootstrap.contextBinding32B64u,
          derivationClientSharePublicKey33B64u: bootstrap.clientSharePublicKey33B64u,
          clientShareRetryCounter: bootstrap.clientShareRetryCounter,
          participantId: 1,
        };
        return await input.runRelayerRound(bootstrap);
      },
    },
  });
  if (!admittedCommitPayload || !clientBootstrap) {
    throw new Error('the EVM custody join reached no activation round');
  }
  if (payload.establishedCustody) {
    throw new Error('an EVM custody join must not establish a second wallet seed');
  }
  if (!payload.ecdsaReadyStateBlobB64u || !payload.ecdsaPublicFacts) {
    throw new Error('the EVM custody join produced no local signing material');
  }
  return {
    commitPayload: admittedCommitPayload,
    clientBootstrap,
    localMaterial: {
      readyStateBlobB64u: payload.ecdsaReadyStateBlobB64u,
      publicFacts: payload.ecdsaPublicFacts,
    },
  };
}

export type RejoinedEvmFamilyCustody = {
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

export type RecoveryCredentialReplacement =
  | { readonly kind: 'preserve_existing' }
  | {
      readonly kind: 'reseal_replacement_passkey';
      readonly factorJson: string;
      readonly factorSecret: ArrayBuffer;
    };

type WalletRecoveryCustodyInput = {
  readonly custodyJson: string;
  readonly recoveryCode: ArrayBuffer;
  readonly recordedKeyManifestDigestB64u: string;
  readonly credentialReplacement: RecoveryCredentialReplacement;
};

function recoveryCeremonyCustody(
  input: WalletRecoveryCustodyInput,
): Extract<
  Parameters<typeof runWalletCustodyKeySetCeremony>[0]['custody'],
  { readonly origin: 'recover' | 'recover_and_reseal' }
> {
  switch (input.credentialReplacement.kind) {
    case 'preserve_existing':
      return {
        origin: 'recover',
        custodyJson: input.custodyJson,
        recoveryCode: input.recoveryCode,
      };
    case 'reseal_replacement_passkey':
      return {
        origin: 'recover_and_reseal',
        custodyJson: input.custodyJson,
        recoveryCode: input.recoveryCode,
        replacementFactorJson: input.credentialReplacement.factorJson,
        replacementFactorSecret: input.credentialReplacement.factorSecret,
      };
    default:
      return assertNeverRecoveryCredentialReplacement(input.credentialReplacement);
  }
}

function assertNeverRecoveryCredentialReplacement(value: never): never {
  throw new Error(`unsupported recovery credential replacement: ${String(value)}`);
}

export type RecoverEvmFamilyCustodyInput = WalletRecoveryCustodyInput & {
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly walletId: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly applicationBindingDigestB64u: string;
  readonly registeredClientRootPublicKey33B64u: string;
  readonly resolveRelayerPublicIdentity: EstablishEvmFamilyCustodyInput['runRelayerRound'];
};

export type RecoveredEvmFamilyCustody = RejoinedEvmFamilyCustody & {
  readonly recoveryReplacementEnvelope: NonNullable<
    WalletCustodyCeremonyCommitPayload['recoveryReplacementEnvelope']
  > | null;
};

export async function recoverEvmFamilyCustodyV1(
  input: RecoverEvmFamilyCustodyInput,
): Promise<RecoveredEvmFamilyCustody> {
  const expectedDigest = await computeWalletCustodyEvmFamilyKeyManifestDigestB64u({
    walletId: input.walletId,
    evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
    clientRootPublicKey33B64u: input.registeredClientRootPublicKey33B64u,
  });
  if (expectedDigest !== input.recordedKeyManifestDigestB64u) {
    throw new Error('EVM recovery manifest digest does not match the registered identity');
  }
  const payload = await runWalletCustodyKeySetCeremony({
    runStep: input.runStep,
    custody: recoveryCeremonyCustody(input),
    keySetRun: {
      keySet: 'evm_family_ecdsa_v1',
      protocolInputsJson: JSON.stringify({
        applicationBindingDigestB64u: input.applicationBindingDigestB64u,
      }),
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      beforeRelayerRound: async () => undefined,
      runRelayerRound: input.resolveRelayerPublicIdentity,
    },
    recordedKeyManifestDigestB64u: input.recordedKeyManifestDigestB64u,
  });
  if (!payload.ecdsaReadyStateBlobB64u || !payload.ecdsaPublicFacts) {
    throw new Error('the EVM recovery produced no local signing material');
  }
  if (payload.clientRootPublicKey33B64u !== input.registeredClientRootPublicKey33B64u) {
    throw new Error('the EVM recovery changed the registered client root public key');
  }
  return {
    readyStateBlobB64u: payload.ecdsaReadyStateBlobB64u,
    publicFacts: payload.ecdsaPublicFacts,
    recoveryReplacementEnvelope: payload.recoveryReplacementEnvelope ?? null,
  };
}

export async function rejoinEvmFamilyCustodyV1(
  input: RejoinEvmFamilyCustodyInput,
): Promise<RejoinedEvmFamilyCustody> {
  const recordedKeyManifestDigestB64u = await computeWalletCustodyEvmFamilyKeyManifestDigestB64u({
    walletId: input.walletId,
    evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
    clientRootPublicKey33B64u: input.registeredClientRootPublicKey33B64u,
  });
  const payload = await runWalletCustodyKeySetCeremony({
    runStep: input.runStep,
    custody: {
      origin: 'join',
      custodyJson: input.custodyJson,
      factorSecret: input.factorSecret,
    },
    keySetRun: {
      keySet: 'evm_family_ecdsa_v1',
      protocolInputsJson: JSON.stringify({
        applicationBindingDigestB64u: input.applicationBindingDigestB64u,
      }),
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      beforeRelayerRound: async () => undefined,
      runRelayerRound: async () => input.relayerPublicIdentityJson,
    },
    recordedKeyManifestDigestB64u,
  });
  if (payload.establishedCustody) {
    throw new Error('an EVM cold unlock must not establish custody');
  }
  if (!payload.ecdsaReadyStateBlobB64u || !payload.ecdsaPublicFacts) {
    throw new Error('the EVM cold unlock produced no local signing material');
  }
  return {
    readyStateBlobB64u: payload.ecdsaReadyStateBlobB64u,
    publicFacts: payload.ecdsaPublicFacts,
  };
}

function appendU32Be(output: number[], value: number): void {
  output.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function appendManifestField(output: number[], label: string, value: Uint8Array): void {
  const labelBytes = new TextEncoder().encode(label);
  appendU32Be(output, labelBytes.length);
  output.push(...labelBytes);
  appendU32Be(output, value.length);
  output.push(...value);
}

export async function computeWalletCustodyEvmFamilyKeyManifestDigestB64u(input: {
  readonly walletId: string;
  readonly evmFamilySigningKeySlotId: string;
  readonly clientRootPublicKey33B64u: string;
}): Promise<string> {
  const walletId = String(input.walletId || '').trim();
  const slotId = String(input.evmFamilySigningKeySlotId || '').trim();
  const clientRootPublicKey = base64UrlDecode(input.clientRootPublicKey33B64u);
  if (!walletId || !slotId || clientRootPublicKey.length !== 33) {
    throw new Error('EVM custody continuity identity is invalid');
  }
  const fields: number[] = [];
  appendManifestField(
    fields,
    'context',
    new TextEncoder().encode('seams/wallet-custody/key-set-manifest/evm-family-ecdsa/v1'),
  );
  appendManifestField(fields, 'walletId', new TextEncoder().encode(walletId));
  appendManifestField(fields, 'evmFamilySigningKeySlotId', new TextEncoder().encode(slotId));
  appendManifestField(fields, 'clientRootPublicKey33', clientRootPublicKey);
  return base64UrlEncode(await sha256Bytes(Uint8Array.from(fields)));
}

export async function computeWalletCustodyNearEd25519KeyManifestDigestB64u(input: {
  readonly walletId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly registeredPublicKeyB64u: string;
}): Promise<string> {
  const walletId = String(input.walletId || '').trim();
  const signingKeyId = String(input.nearEd25519SigningKeyId || '').trim();
  const registeredPublicKey = base64UrlDecode(input.registeredPublicKeyB64u);
  if (!walletId || !signingKeyId || registeredPublicKey.length !== 32) {
    throw new Error('NEAR custody continuity identity is invalid');
  }
  const fields: number[] = [];
  appendManifestField(
    fields,
    'context',
    new TextEncoder().encode('seams/wallet-custody/key-set-manifest/near-ed25519/v1'),
  );
  appendManifestField(fields, 'walletId', new TextEncoder().encode(walletId));
  appendManifestField(fields, 'nearEd25519SigningKeyId', new TextEncoder().encode(signingKeyId));
  appendManifestField(fields, 'registeredPublicKey', registeredPublicKey);
  return base64UrlEncode(await sha256Bytes(Uint8Array.from(fields)));
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
    ed25519ApplicationBindingDigestB64u: _cacheBinding,
    ecdsaReadyStateBlobB64u: _readyState,
    recoveryReplacementEnvelope: _recoveryReplacement,
    ...wire
  } = payload;
  return wire;
}

async function walletCustodyCommitPayloadWithRecoveryCodeLocators(
  payload: WalletCustodyCeremonyCommitPayload,
  issued: IssuedWalletRecoveryCodes,
): Promise<WalletCustodyCeremonyCommitPayload> {
  const established = payload.establishedCustody;
  if (!established) return payload;
  if (established.recoveryManifestKekWraps.length !== issued.codeBytes.length) {
    throw new Error('recovery code and wrap counts do not match');
  }
  const recoveryCodeLocators = await Promise.all(
    issued.codeBytes.map(async (codeBytes, index) => {
      const wrap = established.recoveryManifestKekWraps[index];
      if (!wrap) throw new Error('recovery code and wrap counts do not match');
      return {
        locatorB64u: await deriveRecoveryCodeLocatorV1FromBytes(codeBytes),
        recoveryKeyId: wrap.recoveryKeyId,
      };
    }),
  );
  if (
    new Set(recoveryCodeLocators.map((locator) => locator.locatorB64u)).size !==
    recoveryCodeLocators.length
  ) {
    throw new Error('recovery code locators must be unique');
  }
  return {
    ...payload,
    establishedCustody: {
      ...established,
      recoveryCodeLocators,
    },
  };
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

/**
 * Reproduces one NEAR key set from custody that already exists.
 *
 * This is synced-passkey cold unlock: a browser with empty IndexedDB has the
 * wallet's server-held envelope and its credential, but no cached material. It
 * opens the envelope with the factor, reaches the same seed, derives the same
 * root, and re-runs the Yao protocol against the *registered* public key —
 * reproducing the key set rather than establishing a new one.
 *
 * **It creates no credential and consumes no recovery code.** The run joins
 * existing custody, so it seals no envelope and issues no codes: `finish` is
 * called with nothing to establish, which the ceremony refuses to combine with
 * a joining origin. That refusal is what makes the guarantee structural rather
 * than a promise this function makes.
 *
 * The continuity key is required, not optional. Without it the run would
 * *establish* a key set — registering a second, different key for a wallet
 * that already has one, which no later check would undo.
 */
export type RejoinNearEd25519CustodyInput = Omit<
  EstablishNearEd25519CustodyInput,
  'factorJson' | 'registrationCeremonyId'
> & {
  /** `JoinCustodyWireV1`: the stored envelope binding and its sealed seed. */
  readonly custodyJson: string;
  readonly recoveryLifecycleId: string;
  /** The key this run must reproduce. */
  readonly registeredPublicKeyB64u: string;
  readonly activateRouterRecovery: (
    protocolResultJson: string,
  ) => Promise<RouterAbEd25519YaoRecoveryActivationReceiptV1>;
};

type JoinedNearEd25519CustodyBase = {
  /** No custody records: the wallet already has its envelope and codes. */
  readonly commitPayload: WalletCustodyCeremonyCommitPayload;
  readonly activationReference: EstablishedNearEd25519Custody['activationReference'];
  readonly localMaterial: EstablishedNearEd25519Custody['localMaterial'];
};

export type RejoinedNearEd25519Custody = JoinedNearEd25519CustodyBase & {
  readonly activationResultJson: string;
  readonly activationReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
};

export type JoinNearEd25519CustodyInput = Omit<
  EstablishNearEd25519CustodyInput,
  'walletId' | 'factorJson' | 'continuityRegisteredPublicKeyB64u'
> & {
  /** `JoinCustodyWireV1`: the envelope established by another key set. */
  readonly custodyJson: string;
};

export type JoinedNearEd25519Custody = JoinedNearEd25519CustodyBase;

export type RecoverNearEd25519CustodyInput = WalletRecoveryCustodyInput & {
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly walletId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly recoveryLifecycleId: string;
  readonly yaoAdmission: unknown;
  readonly yaoApplication: unknown;
  readonly participantIds: readonly [number, number];
  readonly registeredPublicKeyB64u: string;
  readonly runRouterRound: (yaoExecuteRequestJson: string) => Promise<string>;
  readonly activateRouterRecovery: (
    protocolResultJson: string,
  ) => Promise<RouterAbEd25519YaoRecoveryActivationReceiptV1>;
};

export type RecoveredNearEd25519Custody = {
  readonly localMaterial: RejoinedNearEd25519Custody['localMaterial'];
  readonly activationResultJson: string;
  readonly activationReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
  readonly recoveryReplacementEnvelope: NonNullable<
    WalletCustodyCeremonyCommitPayload['recoveryReplacementEnvelope']
  > | null;
};

export async function recoverNearEd25519CustodyV1(
  input: RecoverNearEd25519CustodyInput,
): Promise<RecoveredNearEd25519Custody> {
  const expectedDigest = await computeWalletCustodyNearEd25519KeyManifestDigestB64u({
    walletId: input.walletId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    registeredPublicKeyB64u: input.registeredPublicKeyB64u,
  });
  if (expectedDigest !== input.recordedKeyManifestDigestB64u) {
    throw new Error('NEAR recovery manifest digest does not match the registered identity');
  }
  let activationResultJson: string | null = null;
  let activationReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1 | null = null;
  const payload = await runWalletCustodyKeySetCeremony({
    runStep: input.runStep,
    custody: recoveryCeremonyCustody(input),
    keySetRun: {
      keySet: 'near_ed25519_v1',
      protocolInputsJson: JSON.stringify({
        yaoAdmission: input.yaoAdmission,
        yaoApplication: input.yaoApplication,
        clientParticipantId: input.participantIds[0],
        signingWorkerParticipantId: input.participantIds[1],
        continuityRegisteredPublicKeyB64u: input.registeredPublicKeyB64u,
      }),
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      runRouterRound: async (executeRequestJson) => {
        activationResultJson = await input.runRouterRound(executeRequestJson);
        return activationResultJson;
      },
      afterRouterRoundCompleted: async (protocolResultJson) => {
        activationReceipt = await input.activateRouterRecovery(protocolResultJson);
      },
    },
    recordedKeyManifestDigestB64u: input.recordedKeyManifestDigestB64u,
  });
  if (!payload.ed25519LocalMaterialB64u || !payload.ed25519LocalMaterialNonceB64u) {
    throw new Error('the NEAR recovery sealed no local signing material');
  }
  if (!payload.ed25519ApplicationBindingDigestB64u) {
    throw new Error('the NEAR recovery omitted its application binding digest');
  }
  if (!activationResultJson || !activationReceipt) {
    throw new Error('the NEAR recovery produced no Router activation');
  }
  return {
    localMaterial: {
      b64u: payload.ed25519LocalMaterialB64u,
      nonceB64u: payload.ed25519LocalMaterialNonceB64u,
      applicationBindingDigestB64u: payload.ed25519ApplicationBindingDigestB64u,
    },
    activationResultJson,
    activationReceipt,
    recoveryReplacementEnvelope: payload.recoveryReplacementEnvelope ?? null,
  };
}

/**
 * Adds the wallet's first NEAR key set to custody established by EVM.
 *
 * This is a join without a continuity key because registration is creating
 * the NEAR key set for the first time. The envelope and recovery set already
 * exist, so this run writes only the NEAR manifest and local continuity cache.
 */
export async function joinNearEd25519CustodyV1(
  input: JoinNearEd25519CustodyInput,
): Promise<JoinedNearEd25519Custody> {
  return await runJoiningNearEd25519Custody(
    input,
    input.registrationCeremonyId,
    undefined,
    'registration join',
  );
}

export async function rejoinNearEd25519CustodyV1(
  input: RejoinNearEd25519CustodyInput,
): Promise<RejoinedNearEd25519Custody> {
  const registeredPublicKeyB64u = String(input.registeredPublicKeyB64u || '').trim();
  if (!registeredPublicKeyB64u) {
    throw new Error('a cold unlock must name the key set it reproduces');
  }

  let activationResultJson: string | null = null;
  let activationReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1 | null = null;
  const rejoined = await runJoiningNearEd25519Custody(
    input,
    input.recoveryLifecycleId,
    registeredPublicKeyB64u,
    'cold unlock',
    async (protocolResultJson) => {
      activationResultJson = protocolResultJson;
      activationReceipt = await input.activateRouterRecovery(protocolResultJson);
    },
  );
  if (!activationResultJson || !activationReceipt) {
    throw new Error('the NEAR cold unlock produced no Router recovery activation');
  }
  return { ...rejoined, activationResultJson, activationReceipt };
}

async function runJoiningNearEd25519Custody(
  input: Omit<JoinNearEd25519CustodyInput, 'registrationCeremonyId'>,
  lifecycleId: string,
  continuityRegisteredPublicKeyB64u: string | undefined,
  operation: 'registration join' | 'cold unlock',
  afterRouterRoundCompleted?: (protocolResultJson: string) => Promise<void>,
): Promise<JoinedNearEd25519CustodyBase> {
  let activationSessionId: readonly number[] | null = null;
  const payload = await runWalletCustodyKeySetCeremony({
    runStep: input.runStep,
    custody: {
      origin: 'join',
      custodyJson: input.custodyJson,
      factorSecret: input.factorSecret,
    },
    keySetRun: {
      keySet: 'near_ed25519_v1',
      protocolInputsJson: JSON.stringify({
        yaoAdmission: input.yaoAdmission,
        yaoApplication: input.yaoApplication,
        clientParticipantId: input.participantIds[0],
        signingWorkerParticipantId: input.participantIds[1],
        ...(continuityRegisteredPublicKeyB64u ? { continuityRegisteredPublicKeyB64u } : {}),
      }),
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      runRouterRound: async (yaoExecuteRequestJson: string) => {
        const resultJson = await input.runRouterRound(yaoExecuteRequestJson);
        activationSessionId = activationSessionIdFromResult(resultJson);
        return resultJson;
      },
      ...(afterRouterRoundCompleted ? { afterRouterRoundCompleted } : {}),
    },
  });

  if (!activationSessionId) {
    throw new Error(`the NEAR ${operation} produced no activation session id`);
  }
  if (payload.establishedCustody) {
    /* Unreachable through the ceremony, which refuses to seal on a joining
       run. Checked anyway because the failure it guards against — a second
       envelope and a second recovery set for one wallet — is the one this
       whole design exists to prevent. */
    throw new Error(`a NEAR ${operation} must not establish custody`);
  }
  if (!payload.ed25519LocalMaterialB64u || !payload.ed25519LocalMaterialNonceB64u) {
    throw new Error(`the NEAR ${operation} sealed no local material`);
  }

  return {
    commitPayload: walletCustodyCommitPayloadForWire(payload),
    activationReference: {
      kind: 'router_ab_ed25519_yao_activation_reference_v1',
      lifecycle_id: lifecycleId,
      session_id: activationSessionId,
    },
    localMaterial: {
      b64u: payload.ed25519LocalMaterialB64u,
      nonceB64u: payload.ed25519LocalMaterialNonceB64u,
      applicationBindingDigestB64u: String(payload.ed25519ApplicationBindingDigestB64u || ''),
    },
  };
}
