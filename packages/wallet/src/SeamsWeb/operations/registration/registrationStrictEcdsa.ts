/**
 * Strict Router A/B ECDSA family registration: the ceremony, its activation
 * commit, and the wallet-key assertions that guard it.
 *
 * Moved verbatim out of `registration.ts`. This module drives one protocol; it
 * does not decide which protocols a registration runs, which is why the
 * three-route orchestration stayed behind.
 */

import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
  type CorrelationId,
} from '@shared/utils/canonicalPrimitives';
import type {
  RegistrationSigningSurface,
  RegistrationWebContext,
} from '@/SeamsWeb/signingSurface/types';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { WalletId } from '@shared/utils/registrationIntent';
import { base64UrlDecode } from '@shared/utils/base64';
import { toParticipantId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildCanonicalWalletAddSignerEcdsaActivationRequest,
  computeWalletAddSignerEcdsaActivationRequestDigestB64u,
} from '@shared/utils/walletAddSignerActivation';
import {
  activateWalletAddSignerEcdsa,
  parseWalletRegistrationEcdsaDerivationRespond,
  respondWalletAddSignerEcdsa,
  type WalletRegistrationEcdsaDerivationRespondBootstrap,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEcdsaPreparePayload,
} from '@/core/rpcClients/relayer/walletRegistration';
import type {
  PasskeyCustodyEnvelopeRecord,
  WalletCustodyEvmFamilyPublicFacts,
} from '@shared/passkey-custody';
import { joinCustodyWireFromEnvelopeRecord } from '@/core/signingEngine/walletCustody/joinCustodyWire';
import type {
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import { type WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  RegistrationEstablishedEcdsaSessionProjectionV2,
  RegistrationEstablishedSessionProjectionV2,
  RegistrationEstablishedSessionResultV2,
  RegistrationEstablishedSessionV2,
} from '@shared/utils/registrationEstablishedSession';
import {
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import {
  RegistrationTimingRecorder,
  assertNever,
  isRegistrationBenchmarkDiagnosticsEnabled,
} from './registrationTiming';
export function registrationRouteHeaders(
  traceContext?: RouterAbTraceContextV1,
): Record<string, string> | undefined {
  const headers: Record<string, string> = {};
  if (isRegistrationBenchmarkDiagnosticsEnabled()) {
    headers['X-Seams-Benchmark-Diagnostics'] = 'registration-flow';
  }
  if (traceContext) headers[ROUTER_AB_TRACE_ID_HEADER_V1] = traceContext.value;
  return Object.keys(headers).length > 0 ? headers : undefined;
}

function ethereumAddressFromAddress20B64u(value: string): `0x${string}` {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) throw new Error('ECDSA activation returned an invalid address');
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return `0x${hex}`;
}

export type RegistrationEcdsaSession = {
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  authority: FinalizeRouterAbEcdsaRegistrationActivationResultV1['authority'];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  /** Canonical threshold identity returned by the activated server bootstrap. */
  activatedThresholdSessionId: string;
  roleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
  materialActivation: FinalizeRouterAbEcdsaRegistrationActivationResultV1['materialActivation'];
  clientPublicFacts: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicFacts'];
  publicCapability: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicCapability'];
  registrationEstablishedSession: RegistrationEstablishedSessionV2;
};

export class RegistrationExactMethodUnlockRequiredError extends Error {
  readonly code = 'wallet_unlock_required' as const;
  readonly next = 'unlock_exact_method' as const;
  readonly projection: RegistrationEstablishedSessionProjectionV2;

  constructor(projection: RegistrationEstablishedSessionProjectionV2) {
    super('Registration response was already committed; exact-method unlock is required');
    this.name = 'RegistrationExactMethodUnlockRequiredError';
    this.projection = projection;
  }
}

export function requireIssuedRegistrationEstablishedSession(
  result: RegistrationEstablishedSessionResultV2,
): RegistrationEstablishedSessionV2 {
  switch (result.kind) {
    case 'issued':
      return result.session;
    case 'already_committed':
      throw new RegistrationExactMethodUnlockRequiredError(result.session);
    default:
      return assertNever(result);
  }
}

type PendingRegistrationEcdsaLocalFinalization = {
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  activatedThresholdSessionId: string;
  journalId: CorrelationId;
  activationReceipt: FinalizeRouterAbEcdsaRegistrationActivationRequestV1['activationReceipt'];
  custodyKeySet: {
    readonly kind: 'evm_family_ecdsa_v1';
    readonly keyManifestDigestB64u: string;
    readonly clientRootPublicKey33B64u: string;
  };
  custodyLocalMaterial: {
    readonly readyStateBlobB64u: string;
    readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
  };
};

export type RegistrationLocalEcdsaWalletKeys = Awaited<
  ReturnType<RegistrationSigningSurface['finalizeWalletRegistrationEcdsaSessions']>
>;

export function assertSharedRegistrationEvmFamilyWalletKeyMaterial(
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[],
): void {
  const first = walletKeys[0];
  if (!first) return;
  for (const walletKey of walletKeys.slice(1)) {
    const mismatch = firstRegistrationEvmFamilyWalletKeyMaterialMismatch(first, walletKey);
    if (mismatch) {
      throw new Error(
        `ECDSA registration returned partitioned EVM-family wallet key material: ${mismatch}`,
      );
    }
  }
}

export function assertRegistrationWalletKeyCapabilities(args: {
  readonly session: RegistrationEcdsaSession;
  readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
}): void {
  const expected = alphabetizeStringify(args.session.publicCapability);
  for (const walletKey of args.walletKeys) {
    if (alphabetizeStringify(walletKey.publicCapability) !== expected) {
      throw new Error(
        'ECDSA registration wallet key public capability does not match client-verified activation',
      );
    }
  }
}

function firstRegistrationEvmFamilyWalletKeyMaterialMismatch(
  left: WalletRegistrationEcdsaWalletKey,
  right: WalletRegistrationEcdsaWalletKey,
): string | null {
  if (left.keyScope !== 'evm-family' || right.keyScope !== 'evm-family') return 'keyScope';
  if (left.walletId !== right.walletId) return 'walletId';
  if (left.evmFamilySigningKeySlotId !== right.evmFamilySigningKeySlotId)
    return 'evmFamilySigningKeySlotId';
  if (left.keyHandle !== right.keyHandle) return 'keyHandle';
  if (left.ecdsaThresholdKeyId !== right.ecdsaThresholdKeyId) return 'ecdsaThresholdKeyId';
  if (left.signingRootId !== right.signingRootId) return 'signingRootId';
  if (left.signingRootVersion !== right.signingRootVersion) return 'signingRootVersion';
  if (left.thresholdEcdsaPublicKeyB64u !== right.thresholdEcdsaPublicKeyB64u)
    return 'thresholdEcdsaPublicKeyB64u';
  if (
    left.thresholdOwnerAddress.trim().toLowerCase() !==
    right.thresholdOwnerAddress.trim().toLowerCase()
  )
    return 'thresholdOwnerAddress';
  if (left.relayerKeyId !== right.relayerKeyId) return 'relayerKeyId';
  if (left.relayerVerifyingShareB64u !== right.relayerVerifyingShareB64u)
    return 'relayerVerifyingShareB64u';
  if (left.participantIds.join(',') !== right.participantIds.join(',')) return 'participantIds';
  return null;
}

export function registrationChainTargetListsMatch(
  left: readonly ThresholdEcdsaChainTarget[],
  right: readonly ThresholdEcdsaChainTarget[],
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    const leftTarget = left[index];
    const rightTarget = right[index];
    if (!leftTarget || !rightTarget) return false;
    if (thresholdEcdsaChainTargetKey(leftTarget) !== thresholdEcdsaChainTargetKey(rightTarget)) {
      return false;
    }
  }
  return true;
}

export async function closeStrictEcdsaRegistrationCeremony(args: {
  context: RegistrationWebContext;
  ceremonyId: string;
}): Promise<void> {
  try {
    await args.context.signingEngine.closeRouterAbEcdsaRegistrationCeremony({
      kind: 'close_router_ab_ecdsa_registration_ceremony_v1',
      ceremonyId: args.ceremonyId,
    });
  } catch {
    return;
  }
}

export function buildStrictRegistrationClientBootstrap(args: {
  prepare: WalletRegistrationEcdsaPreparePayload['prepare'];
  verified: Awaited<
    ReturnType<RegistrationWebContext['signingEngine']['joinWalletCustodyEvmFamilyKeySet']>
  >['clientBootstrap'];
}): WalletRegistrationEcdsaClientBootstrap {
  const prepare = args.prepare;
  return {
    formatVersion: prepare.formatVersion,
    walletId: prepare.walletId,
    evmFamilySigningKeySlotId: prepare.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: prepare.ecdsaThresholdKeyId,
    signingRootId: prepare.signingRootId,
    signingRootVersion: prepare.signingRootVersion,
    keyScope: prepare.keyScope,
    relayerKeyId: prepare.relayerKeyId,
    registrationPreparationId: prepare.registrationPreparationId,
    requestId: prepare.requestId,
    thresholdSessionId: prepare.thresholdSessionId,
    ttlMs: prepare.ttlMs,
    remainingUses: prepare.remainingUses,
    participantIds: [...prepare.participantIds],
    runtimePolicyScope: prepare.runtimePolicyScope,
    derivationClientSharePublicKey33B64u: args.verified.derivationClientSharePublicKey33B64u,
    clientShareRetryCounter: args.verified.clientShareRetryCounter,
    contextBinding32B64u: args.verified.contextBinding32B64u,
  };
}

/**
 * The client-computed activation command — the add-signer counterpart of
 * registration's `buildThreeRouteCanonicalActivationCommand`. The digest the
 * server used to hand back from the deleted activate/prepare route is now
 * derived locally from the canonical command, journaled, and asserted against
 * the receipt at finalize.
 */
async function buildAddSignerCanonicalActivationCommand(args: {
  addSignerCeremonyId: string;
  activationCorrelationId: CorrelationId;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
}) {
  return {
    canonicalRequest: buildCanonicalWalletAddSignerEcdsaActivationRequest(args),
    requestDigest: parseDigestB64u(
      await computeWalletAddSignerEcdsaActivationRequestDigestB64u(args),
    ),
  };
}

async function activateAddSignerEcdsaWithReplayReconciliation(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  activationCorrelationId: CorrelationId;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  expectedActivationRequestDigest: RouterAbPublicDigest32V1Wire;
}) {
  try {
    return await activateWalletAddSignerEcdsa(args);
  } catch {
    /* The server activate is idempotent under these canonical coordinates: a
       first attempt that committed before the failure replays its receipt, one
       that never claimed is claimed now. Exact replay stays enforced — the
       finalize journal rejects a receipt that does not match the journaled
       command. */
    return await activateWalletAddSignerEcdsa(args);
  }
}

type StrictEcdsaCeremonyTimingBucket =
  | 'ecdsaRegistrationClientCreateMs'
  | 'ecdsaRegistrationGatewayRespondMs'
  | 'ecdsaRegistrationClientProofVerifyMs'
  | 'ecdsaRegistrationGatewayActivateMs'
  | 'ecdsaRegistrationClientActivationFinalizeMs';

export async function measureStrictEcdsaCeremonyStep<T>(args: {
  registrationTiming: RegistrationTimingRecorder | null;
  bucket: StrictEcdsaCeremonyTimingBucket;
  operation: () => Promise<T>;
}): Promise<T> {
  if (!args.registrationTiming) return await args.operation();
  return await args.registrationTiming.measure(args.bucket, args.operation);
}

export async function runStrictEcdsaFamilyCeremony(args: {
  context: RegistrationWebContext;
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  started: WalletRegistrationEcdsaPreparePayload;
  custodyEnvelope: PasskeyCustodyEnvelopeRecord;
  factorSecret: ArrayBuffer;
  authority: WalletAuthAuthorityRef;
  registrationTiming: RegistrationTimingRecorder | null;
}): Promise<PendingRegistrationEcdsaLocalFinalization> {
  const [firstChainTarget, ...remainingChainTargets] = args.started.chainTargets;
  if (!firstChainTarget) {
    throw new Error('Strict ECDSA ceremony requires at least one EVM-family target');
  }
  const ceremonyId = args.addSignerCeremonyId;
  const activationCorrelationId = parseCorrelationId(ceremonyId);
  try {
    const created = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientCreateMs',
      operation: args.context.signingEngine.createRouterAbEcdsaRegistrationCeremony.bind(
        args.context.signingEngine,
        {
          kind: 'create_router_ab_ecdsa_registration_ceremony_v1',
          ceremonyId,
          registration: args.started.strictRegistration,
        },
      ),
    });
    const forwarded = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayRespondMs',
      operation: respondWalletAddSignerEcdsa.bind(undefined, {
        relayerUrl: args.relayerUrl,
        walletId: args.walletId,
        addSignerCeremonyId: ceremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: created.registrationRequest,
          requestDigestB64u: created.registrationRequestDigestB64u,
        },
      }),
    });
    const verified = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientProofVerifyMs',
      operation: args.context.signingEngine.verifyRouterAbEcdsaRegistrationClientProofs.bind(
        args.context.signingEngine,
        {
          kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1',
          bootstrapOwner: 'wallet_custody',
          ceremonyId,
          clientProofFinalization: {
            kind: 'finalize_encrypted_client_proof_bundles_v1',
            bundles: forwarded.ecdsa.strictResult.response.bundles,
          },
        },
      ),
    });
    const custodyWire = joinCustodyWireFromEnvelopeRecord(args.custodyEnvelope);
    if (!custodyWire.ok) throw new Error(custodyWire.reason);
    const activation = {
      response: null as Awaited<
        ReturnType<typeof activateAddSignerEcdsaWithReplayReconciliation>
      > | null,
      journalId: null as CorrelationId | null,
    };
    const joined = await args.context.signingEngine.joinWalletCustodyEvmFamilyKeySet({
      walletId: args.walletId,
      custodyJson: custodyWire.custodyJson,
      factorSecret: args.factorSecret,
      evmFamilySigningKeySlotId: args.started.prepare.evmFamilySigningKeySlotId,
      applicationBindingDigestB64u: verified.applicationBindingDigestB64u,
      runRelayerRound: async (bootstrap) => {
        const publicFacts = parseRouterAbEcdsaVerifiedClientActivationFactsV1({
          registrationRequestDigestB64u: verified.registrationRequestDigestB64u,
          proofTranscriptDigestB64u: verified.proofTranscriptDigestB64u,
          contextBinding32B64u: bootstrap.contextBinding32B64u,
          derivationClientSharePublicKey33B64u: bootstrap.clientSharePublicKey33B64u,
          clientShareRetryCounter: bootstrap.clientShareRetryCounter,
          participantId: 1,
        });
        const activationCommand = await buildAddSignerCanonicalActivationCommand({
          addSignerCeremonyId: ceremonyId,
          activationCorrelationId,
          publicFacts,
        });
        const expectedActivationRequestDigest: RouterAbPublicDigest32V1Wire = {
          bytes: Array.from(base64UrlDecode(String(activationCommand.requestDigest))),
        };
        const persisted = await args.context.signingEngine.persistInitialCanonicalEcdsaActivation({
          kind: 'persist_initial_canonical_ecdsa_activation_v1',
          bootstrapOwner: 'wallet_custody',
          ceremonyId,
          clientActivation: publicFacts,
          planInput: {
            authority: args.authority,
            targetMemberships: [firstChainTarget, ...remainingChainTargets],
            evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
              args.started.prepare.evmFamilySigningKeySlotId,
              'registration ECDSA signing key slot',
            ),
            ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(args.started.prepare.ecdsaThresholdKeyId),
            signingRootId: parseSdkEcdsaDerivationSigningRootId(args.started.prepare.signingRootId),
            signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
              args.started.prepare.signingRootVersion,
            ),
            runtimePolicyScope: args.started.prepare.runtimePolicyScope,
            clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
              bootstrap.clientSharePublicKey33B64u,
            ),
            participantIds: [
              toParticipantId(args.started.prepare.participantIds[0]),
              toParticipantId(args.started.prepare.participantIds[1]),
            ],
            relayerKeyId: parseEcdsaRelayerKeyId(args.started.prepare.relayerKeyId),
            bindingDigest: parseEcdsaRoleLocalBindingDigest(bootstrap.contextBinding32B64u),
            journalId: activationCorrelationId,
            requestDigest: activationCommand.requestDigest,
            canonicalRequest: activationCommand.canonicalRequest,
            createdAt: parseIsoTimestamp(new Date().toISOString()),
          },
        });
        if (!persisted.ok) {
          throw new Error(
            `Canonical ECDSA activation persistence failed (${persisted.code}): ${persisted.message}`,
          );
        }
        activation.journalId = persisted.journalId;
        activation.response = await measureStrictEcdsaCeremonyStep({
          registrationTiming: args.registrationTiming,
          bucket: 'ecdsaRegistrationGatewayActivateMs',
          operation: activateAddSignerEcdsaWithReplayReconciliation.bind(undefined, {
            relayerUrl: args.relayerUrl,
            walletId: args.walletId,
            addSignerCeremonyId: ceremonyId,
            activationCorrelationId,
            publicFacts,
            expectedActivationRequestDigest,
          }),
        });
        const identity = activation.response.ecdsa.activation.ecdsa_activation.public_identity;
        return JSON.stringify({
          relayerKeyId: args.started.prepare.relayerKeyId,
          relayerPublicKey33B64u: identity.server_public_key33_b64u,
          groupPublicKey33B64u: identity.threshold_public_key33_b64u,
          ethereumAddress: ethereumAddressFromAddress20B64u(identity.ethereum_address20_b64u),
          relayerShareRetryCounter: identity.server_share_retry_counter,
        });
      },
    });
    if (!activation.response || !activation.journalId) {
      throw new Error('Add-signer ECDSA custody join did not activate');
    }
    const activated = activation.response;
    const journalId = activation.journalId;
    const clientRootPublicKey33B64u = joined.commitPayload.clientRootPublicKey33B64u;
    if (!clientRootPublicKey33B64u) {
      throw new Error('Add-signer ECDSA custody join returned no client root public key');
    }
    const clientBootstrap = buildStrictRegistrationClientBootstrap({
      prepare: args.started.prepare,
      verified: joined.clientBootstrap,
    });
    const bootstrap = parseWalletRegistrationEcdsaDerivationRespond({
      clientBootstrap,
      serverBootstrap: activated.ecdsa.bootstrap,
      activationEpoch: activated.ecdsa.activation.ecdsa_activation.activation_epoch,
    });
    return {
      chainTargets: [firstChainTarget, ...remainingChainTargets],
      clientBootstrap,
      bootstrap,
      activatedThresholdSessionId: activated.ecdsa.bootstrap.thresholdSessionId,
      journalId,
      activationReceipt: activated.ecdsa.activation,
      custodyKeySet: {
        kind: 'evm_family_ecdsa_v1',
        keyManifestDigestB64u: joined.commitPayload.keyManifestDigestB64u,
        clientRootPublicKey33B64u,
      },
      custodyLocalMaterial: joined.localMaterial,
    };
  } catch (error: unknown) {
    await closeStrictEcdsaRegistrationCeremony({
      context: args.context,
      ceremonyId,
    });
    throw error;
  }
}

export async function finalizeStrictEcdsaFamilyLocalActivation(args: {
  context: RegistrationWebContext;
  pending: PendingRegistrationEcdsaLocalFinalization;
}): Promise<Omit<RegistrationEcdsaSession, 'registrationEstablishedSession'>> {
  const finalized = await args.context.signingEngine.finalizeRouterAbEcdsaRegistrationActivation({
    kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
    bootstrapOwner: 'wallet_custody',
    journalId: args.pending.journalId,
    activationReceipt: args.pending.activationReceipt,
    routerAbEcdsaDerivationNormalSigning:
      args.pending.bootstrap.routerAbEcdsaDerivationNormalSigning,
    readyStateBlobB64u: args.pending.custodyLocalMaterial.readyStateBlobB64u,
    walletCustodyPublicFacts: args.pending.custodyLocalMaterial.publicFacts,
  });
  return {
    chainTargets: args.pending.chainTargets,
    authority: finalized.authority,
    clientBootstrap: args.pending.clientBootstrap,
    bootstrap: args.pending.bootstrap,
    activatedThresholdSessionId: args.pending.activatedThresholdSessionId,
    roleLocalMaterial: finalized.roleLocalMaterial,
    materialActivation: finalized.materialActivation,
    clientPublicFacts: finalized.publicFacts,
    publicCapability: finalized.publicCapability,
  };
}

function registrationEstablishedEcdsaSession(
  session: RegistrationEstablishedSessionV2,
): RegistrationEstablishedEcdsaSessionProjectionV2 {
  switch (session.tokens.kind) {
    case 'evm_family_ecdsa':
    case 'near_ed25519_and_evm_family_ecdsa':
      return session.tokens.ecdsa;
    case 'near_ed25519':
      throw new Error('Registration-established session is missing ECDSA authorization');
    default:
      return assertNever(session.tokens);
  }
}

export function assertRegistrationEcdsaSessionMatchesWalletKeys(args: {
  session: RegistrationEcdsaSession;
  walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
}): void {
  const [firstWalletKey] = args.walletKeys;
  if (!firstWalletKey) {
    throw new Error('ECDSA registration did not return wallet key material');
  }
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  if (
    String(args.session.registrationEstablishedSession.walletId) !== firstWalletKey.walletId ||
    token.thresholdSessionId !== args.session.activatedThresholdSessionId ||
    token.keyHandle !== firstWalletKey.keyHandle ||
    !sameRuntimePolicyScope(
      token.runtimePolicyScope,
      args.session.clientBootstrap.runtimePolicyScope,
    ) ||
    alphabetizeStringify(token.routerAbEcdsaDerivationNormalSigning) !==
      alphabetizeStringify(args.session.bootstrap.routerAbEcdsaDerivationNormalSigning)
  ) {
    throw new Error('Registration-established ECDSA session changed the signer identity');
  }
  for (const walletKey of args.walletKeys) {
    if (
      walletKey.walletId !== firstWalletKey.walletId ||
      walletKey.keyHandle !== token.keyHandle ||
      walletKey.ecdsaThresholdKeyId !== firstWalletKey.ecdsaThresholdKeyId
    ) {
      throw new Error('ECDSA registration material changed the established session identity');
    }
  }
}

export function sameRuntimePolicyScope(
  left: ReturnType<typeof normalizeRuntimePolicyScope>,
  right: ReturnType<typeof normalizeRuntimePolicyScope>,
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}
