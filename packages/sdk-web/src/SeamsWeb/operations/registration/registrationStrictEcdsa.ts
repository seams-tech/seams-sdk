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
import { base64UrlEncode } from '@shared/utils/base64';
import {
  toParticipantId,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
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
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  activateWalletAddSignerEcdsa,
  activateWalletRegistrationEcdsa,
  canonicalWalletAddSignerEcdsaActivationCommitRequest,
  canonicalWalletRegistrationEcdsaActivationCommitRequest,
  parseWalletRegistrationEcdsaDerivationRespond,
  prepareWalletAddSignerEcdsaActivation,
  prepareWalletRegistrationEcdsaActivation,
  queryWalletAddSignerEcdsaActivation,
  queryWalletRegistrationEcdsaActivation,
  respondWalletAddSignerEcdsa,
  respondWalletRegistrationEcdsa,
  type WalletRegistrationEcdsaDerivationRespondBootstrap,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaWalletKey,
  type WalletRegistrationEcdsaPreparePayload,
} from '@/core/rpcClients/relayer/walletRegistration';
import type {
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import { type WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  RegistrationEstablishedEcdsaSession,
  RegistrationEstablishedSession,
} from '@shared/utils/registrationEstablishedSession';
import type { SealedSigningSessionEcdsaRestoreMetadata } from '@shared/utils/signingSessionSeal';
import {
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import {
  RegistrationTimingRecorder,
  assertNever,
  isRegistrationBenchmarkDiagnosticsEnabled,
  recordStrictEcdsaServerTimingBuckets,
} from './registrationTiming';
import type { RegistrationPersistenceAuth } from './registration';
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
  registrationEstablishedSession: RegistrationEstablishedSession;
};

type PendingRegistrationEcdsaLocalFinalization = {
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  bootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  activatedThresholdSessionId: string;
  journalId: CorrelationId;
  activationReceipt: FinalizeRouterAbEcdsaRegistrationActivationRequestV1['activationReceipt'];
};

export type RegistrationLocalEcdsaWalletKeys = Awaited<
  ReturnType<RegistrationSigningSurface['finalizeWalletRegistrationEcdsaSessions']>
>;

type RegistrationPasskeyEcdsaWarmSession = {
  readonly transport: {
    readonly curve: 'ecdsa';
    readonly authMethod: 'passkey';
    readonly walletId: string;
    readonly chainTarget: ThresholdEcdsaChainTarget;
    readonly relayerUrl: string;
    readonly walletSessionJwt: string;
    readonly ecdsaRestore: Exclude<
      SealedSigningSessionEcdsaRestoreMetadata,
      { source: 'email_otp' }
    >;
  };
};

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

function registrationParticipantIdsMatch(
  left: readonly number[],
  right: readonly number[],
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
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
    ReturnType<
      RegistrationWebContext['signingEngine']['verifyRouterAbEcdsaRegistrationClientProofs']
    >
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

type StrictEcdsaFamilyCeremonyRoute =
  | {
      kind: 'registration';
      registrationCeremonyId: string;
      walletId?: never;
      addSignerCeremonyId?: never;
    }
  | {
      kind: 'add_signer';
      walletId: WalletId;
      addSignerCeremonyId: string;
      registrationCeremonyId?: never;
    };

function strictEcdsaFamilyCeremonyId(route: StrictEcdsaFamilyCeremonyRoute): string {
  switch (route.kind) {
    case 'registration':
      return route.registrationCeremonyId;
    case 'add_signer':
      return route.addSignerCeremonyId;
    default:
      return assertNever(route);
  }
}

async function forwardStrictEcdsaFamilyRegistration(args: {
  relayerUrl: string;
  route: StrictEcdsaFamilyCeremonyRoute;
  traceContext?: RouterAbTraceContextV1;
  strictRegistration: Awaited<
    ReturnType<RegistrationWebContext['signingEngine']['createRouterAbEcdsaRegistrationCeremony']>
  >['registrationRequest'];
  onServerTiming?: (header: string | null) => void;
}) {
  switch (args.route.kind) {
    case 'registration':
      return await respondWalletRegistrationEcdsa({
        relayerUrl: args.relayerUrl,
        headers: registrationRouteHeaders(args.traceContext),
        registrationCeremonyId: args.route.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: args.strictRegistration,
        },
        ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
      });
    case 'add_signer':
      return await respondWalletAddSignerEcdsa({
        relayerUrl: args.relayerUrl,
        walletId: args.route.walletId,
        addSignerCeremonyId: args.route.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: args.strictRegistration,
        },
      });
    default:
      return assertNever(args.route);
  }
}

async function prepareStrictEcdsaFamilyActivation(args: {
  relayerUrl: string;
  route: StrictEcdsaFamilyCeremonyRoute;
  activationCorrelationId: CorrelationId;
  traceContext?: RouterAbTraceContextV1;
  publicFacts: Parameters<typeof activateWalletRegistrationEcdsa>[0]['publicFacts'];
  onServerTiming?: (header: string | null) => void;
}) {
  switch (args.route.kind) {
    case 'registration':
      return (
        await prepareWalletRegistrationEcdsaActivation({
          relayerUrl: args.relayerUrl,
          headers: registrationRouteHeaders(args.traceContext),
          registrationCeremonyId: args.route.registrationCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
          ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
        })
      ).ecdsa.preparation;
    case 'add_signer':
      return (
        await prepareWalletAddSignerEcdsaActivation({
          relayerUrl: args.relayerUrl,
          walletId: args.route.walletId,
          addSignerCeremonyId: args.route.addSignerCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
        })
      ).ecdsa.preparation;
    default:
      return assertNever(args.route);
  }
}

type StrictEcdsaActivationCommitInput = {
  route: StrictEcdsaFamilyCeremonyRoute;
  activationCorrelationId: CorrelationId;
  publicFacts: Parameters<typeof activateWalletRegistrationEcdsa>[0]['publicFacts'];
  expectedActivationRequestDigest: Parameters<
    typeof activateWalletRegistrationEcdsa
  >[0]['expectedActivationRequestDigest'];
};

function canonicalStrictEcdsaFamilyActivationRequest(input: StrictEcdsaActivationCommitInput) {
  switch (input.route.kind) {
    case 'registration':
      return canonicalWalletRegistrationEcdsaActivationCommitRequest({
        registrationCeremonyId: input.route.registrationCeremonyId,
        activationCorrelationId: input.activationCorrelationId,
        publicFacts: input.publicFacts,
        expectedActivationRequestDigest: input.expectedActivationRequestDigest,
      });
    case 'add_signer':
      return canonicalWalletAddSignerEcdsaActivationCommitRequest({
        addSignerCeremonyId: input.route.addSignerCeremonyId,
        activationCorrelationId: input.activationCorrelationId,
        publicFacts: input.publicFacts,
        expectedActivationRequestDigest: input.expectedActivationRequestDigest,
      });
    default:
      return assertNever(input.route);
  }
}

async function activateStrictEcdsaFamilyRegistration(
  args: StrictEcdsaActivationCommitInput & {
    materialActivation: RouterAbMpcMaterialActivationRefWire;
    relayerUrl: string;
    traceContext?: RouterAbTraceContextV1;
    onServerTiming?: (header: string | null) => void;
  },
) {
  switch (args.route.kind) {
    case 'registration':
      return await activateWalletRegistrationEcdsa({
        relayerUrl: args.relayerUrl,
        headers: registrationRouteHeaders(args.traceContext),
        registrationCeremonyId: args.route.registrationCeremonyId,
        activationCorrelationId: args.activationCorrelationId,
        publicFacts: args.publicFacts,
        expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        materialActivation: args.materialActivation,
        ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
      });
    case 'add_signer':
      return await activateWalletAddSignerEcdsa({
        relayerUrl: args.relayerUrl,
        walletId: args.route.walletId,
        addSignerCeremonyId: args.route.addSignerCeremonyId,
        activationCorrelationId: args.activationCorrelationId,
        publicFacts: args.publicFacts,
        expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        materialActivation: args.materialActivation,
      });
    default:
      return assertNever(args.route);
  }
}

async function queryStrictEcdsaFamilyActivation(
  args: StrictEcdsaActivationCommitInput & {
    relayerUrl: string;
    traceContext?: RouterAbTraceContextV1;
  },
) {
  switch (args.route.kind) {
    case 'registration':
      return (
        await queryWalletRegistrationEcdsaActivation({
          relayerUrl: args.relayerUrl,
          headers: registrationRouteHeaders(args.traceContext),
          registrationCeremonyId: args.route.registrationCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
          expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        })
      ).ecdsa.result;
    case 'add_signer':
      return (
        await queryWalletAddSignerEcdsaActivation({
          relayerUrl: args.relayerUrl,
          walletId: args.route.walletId,
          addSignerCeremonyId: args.route.addSignerCeremonyId,
          activationCorrelationId: args.activationCorrelationId,
          publicFacts: args.publicFacts,
          expectedActivationRequestDigest: args.expectedActivationRequestDigest,
        })
      ).ecdsa.result;
    default:
      return assertNever(args.route);
  }
}

function assertActivationQueryCoordinates(
  result: Extract<
    Awaited<ReturnType<typeof queryStrictEcdsaFamilyActivation>>,
    { readonly kind: 'not_committed' }
  >,
  input: StrictEcdsaActivationCommitInput,
): void {
  if (
    result.activation_correlation_id !== input.activationCorrelationId ||
    alphabetizeStringify(result.activation_request_digest) !==
      alphabetizeStringify(input.expectedActivationRequestDigest)
  ) {
    throw new Error('ECDSA activation query changed the prepared activation coordinates');
  }
}

async function activateStrictEcdsaFamilyRegistrationWithReconciliation(
  args: StrictEcdsaActivationCommitInput & {
    materialActivation: RouterAbMpcMaterialActivationRefWire;
    relayerUrl: string;
    traceContext?: RouterAbTraceContextV1;
    onServerTiming?: (header: string | null) => void;
  },
) {
  try {
    return await activateStrictEcdsaFamilyRegistration(args);
  } catch {
    const queried = await queryStrictEcdsaFamilyActivation(args);
    switch (queried.kind) {
      case 'committed': {
        const replayed = await activateStrictEcdsaFamilyRegistration(args);
        if (
          alphabetizeStringify(replayed.ecdsa.activation) !== alphabetizeStringify(queried.receipt)
        ) {
          throw new Error('ECDSA activation replay changed the committed receipt');
        }
        return replayed;
      }
      case 'not_committed':
        assertActivationQueryCoordinates(queried, args);
        return await activateStrictEcdsaFamilyRegistration(args);
      case 'correlation_conflict':
        throw new Error('ECDSA activation query reported a correlation conflict');
      default:
        return assertNever(queried);
    }
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
  route: StrictEcdsaFamilyCeremonyRoute;
  traceContext?: RouterAbTraceContextV1;
  started: WalletRegistrationEcdsaPreparePayload;
  authority: WalletAuthAuthorityRef;
  registrationTiming: RegistrationTimingRecorder | null;
}): Promise<PendingRegistrationEcdsaLocalFinalization> {
  const [firstChainTarget, ...remainingChainTargets] = args.started.chainTargets;
  if (!firstChainTarget) {
    throw new Error('Strict ECDSA ceremony requires at least one EVM-family target');
  }
  const ceremonyId = strictEcdsaFamilyCeremonyId(args.route);
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
      operation: forwardStrictEcdsaFamilyRegistration.bind(undefined, {
        relayerUrl: args.relayerUrl,
        route: args.route,
        traceContext: args.traceContext,
        strictRegistration: created.registrationRequest,
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'respond', header),
      }),
    });
    const verified = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationClientProofVerifyMs',
      operation: args.context.signingEngine.verifyRouterAbEcdsaRegistrationClientProofs.bind(
        args.context.signingEngine,
        {
          kind: 'verify_router_ab_ecdsa_registration_client_proofs_v1',
          ceremonyId,
          clientProofFinalization: {
            kind: 'finalize_encrypted_client_proof_bundles_v1',
            bundles: forwarded.ecdsa.strictResult.response.bundles,
          },
        },
      ),
    });
    const activationPreparation = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayActivateMs',
      operation: prepareStrictEcdsaFamilyActivation.bind(undefined, {
        relayerUrl: args.relayerUrl,
        route: args.route,
        activationCorrelationId,
        traceContext: args.traceContext,
        publicFacts: verified.publicFacts,
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'activate', header),
      }),
    });
    const expectedActivationRequestDigest = activationPreparation.activation_request_digest;
    const canonicalRequest = canonicalStrictEcdsaFamilyActivationRequest({
      route: args.route,
      activationCorrelationId,
      publicFacts: verified.publicFacts,
      expectedActivationRequestDigest,
    });
    const persisted = await args.context.signingEngine.persistInitialCanonicalEcdsaActivation({
      kind: 'persist_initial_canonical_ecdsa_activation_v1',
      ceremonyId,
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
          verified.publicFacts.derivationClientSharePublicKey33B64u,
        ),
        participantIds: [
          toParticipantId(args.started.prepare.participantIds[0]),
          toParticipantId(args.started.prepare.participantIds[1]),
        ],
        relayerKeyId: parseEcdsaRelayerKeyId(args.started.prepare.relayerKeyId),
        bindingDigest: parseEcdsaRoleLocalBindingDigest(verified.publicFacts.contextBinding32B64u),
        journalId: activationCorrelationId,
        requestDigest: parseDigestB64u(
          base64UrlEncode(Uint8Array.from(expectedActivationRequestDigest.bytes)),
        ),
        canonicalRequest,
        createdAt: parseIsoTimestamp(new Date().toISOString()),
      },
    });
    if (!persisted.ok) {
      throw new Error(
        `Canonical ECDSA activation persistence failed (${persisted.code}): ${persisted.message}`,
      );
    }
    const activated = await measureStrictEcdsaCeremonyStep({
      registrationTiming: args.registrationTiming,
      bucket: 'ecdsaRegistrationGatewayActivateMs',
      operation: activateStrictEcdsaFamilyRegistrationWithReconciliation.bind(undefined, {
        relayerUrl: args.relayerUrl,
        route: args.route,
        traceContext: args.traceContext,
        activationCorrelationId,
        materialActivation: persisted.materialActivation,
        publicFacts: verified.publicFacts,
        expectedActivationRequestDigest,
        onServerTiming: (header) =>
          recordStrictEcdsaServerTimingBuckets(args.registrationTiming, 'activate', header),
      }),
    });
    const clientBootstrap = buildStrictRegistrationClientBootstrap({
      prepare: args.started.prepare,
      verified: verified.clientBootstrap,
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
      journalId: persisted.journalId,
      activationReceipt: activated.ecdsa.activation,
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
    journalId: args.pending.journalId,
    activationReceipt: args.pending.activationReceipt,
    routerAbEcdsaDerivationNormalSigning:
      args.pending.bootstrap.routerAbEcdsaDerivationNormalSigning,
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
  session: RegistrationEstablishedSession,
): RegistrationEstablishedEcdsaSession {
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

function buildRegistrationPasskeyEcdsaRestoreMetadata(args: {
  session: RegistrationEcdsaSession;
  walletKey: Awaited<
    ReturnType<RegistrationSigningSurface['finalizeWalletRegistrationEcdsaSessions']>
  >[number];
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
}): Exclude<SealedSigningSessionEcdsaRestoreMetadata, { source: 'email_otp' }> {
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  if (args.walletKey.walletId !== String(args.session.authority.walletId)) {
    throw new Error('Registration ECDSA runtime wallet does not match its authority');
  }
  if (
    alphabetizeStringify(args.walletKey.roleLocalMaterialRef.materialActivation) !==
    alphabetizeStringify(args.session.materialActivation)
  ) {
    throw new Error('Registration ECDSA runtime material activation does not match the session');
  }
  if (
    !args.session.chainTargets.some(
      (chainTarget) =>
        thresholdEcdsaChainTargetKey(chainTarget) ===
        thresholdEcdsaChainTargetKey(args.walletKey.chainTarget),
    )
  ) {
    throw new Error('Registration ECDSA runtime target is outside the activated family');
  }
  const publicFacts = args.walletKey.ecdsaRoleLocalPublicFacts;
  if (
    publicFacts.walletId !== args.walletKey.walletId ||
    thresholdEcdsaChainTargetKey(publicFacts.chainTarget) !==
      thresholdEcdsaChainTargetKey(args.walletKey.chainTarget) ||
    publicFacts.keyHandle !== args.walletKey.keyHandle ||
    publicFacts.ecdsaThresholdKeyId !== args.walletKey.ecdsaThresholdKeyId ||
    alphabetizeStringify(publicFacts.publicCapability) !==
      alphabetizeStringify(args.session.publicCapability)
  ) {
    throw new Error('Registration ECDSA runtime public facts do not match the activated family');
  }
  const credentialIdB64u = String(
    args.auth.credential.rawId || args.auth.credential.id || '',
  ).trim();
  if (!credentialIdB64u) {
    throw new Error('Registration passkey authority is missing its credential identity');
  }
  return {
    chainTarget: args.walletKey.chainTarget,
    signingRootId: args.walletKey.signingRootId,
    signingRootVersion: args.walletKey.signingRootVersion,
    source: 'registration',
    authority: args.session.authority,
    roleLocalMaterialRef: args.walletKey.roleLocalMaterialRef,
    rpId: toRpId(args.auth.rpId),
    credentialIdB64u,
    keyHandle: token.keyHandle,
    ecdsaThresholdKeyId: args.walletKey.ecdsaThresholdKeyId,
    ethereumAddress: args.walletKey.thresholdOwnerAddress,
    relayerKeyId: args.walletKey.relayerKeyId,
    clientVerifyingShareB64u:
      args.walletKey.ecdsaRoleLocalPublicFacts.derivationClientSharePublicKey33B64u,
    thresholdEcdsaPublicKeyB64u: args.walletKey.thresholdEcdsaPublicKeyB64u,
    participantIds: [...args.walletKey.participantIds],
    runtimePolicyScope: token.runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: token.routerAbEcdsaDerivationNormalSigning,
    publicCapability: args.walletKey.publicCapability,
  };
}

export function buildRegistrationPasskeyEcdsaWarmSessions(args: {
  relayerUrl: string;
  session: RegistrationEcdsaSession;
  walletKeys: RegistrationLocalEcdsaWalletKeys;
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
}): RegistrationPasskeyEcdsaWarmSession[] {
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  return args.walletKeys.map((walletKey) => {
    const ecdsaRestore = buildRegistrationPasskeyEcdsaRestoreMetadata({
      session: args.session,
      walletKey,
      auth: args.auth,
    });
    return {
      transport: {
        curve: 'ecdsa',
        authMethod: 'passkey',
        walletId: walletKey.walletId,
        chainTarget: walletKey.chainTarget,
        relayerUrl: args.relayerUrl,
        walletSessionJwt: token.walletSessionJwt,
        ecdsaRestore,
      },
    };
  });
}

export async function persistRegistrationPasskeyEcdsaWarmSessions(args: {
  context: RegistrationWebContext;
  session: RegistrationEcdsaSession;
  warmSessions: readonly RegistrationPasskeyEcdsaWarmSession[];
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
}): Promise<void> {
  const token = registrationEstablishedEcdsaSession(args.session.registrationEstablishedSession);
  const persistTransport =
    args.context.configs.signing.sessionPersistenceMode === 'sealed_refresh_v1';
  for (const warmSession of args.warmSessions) {
    await args.context.signingEngine.hydrateSigningSession({
      thresholdSessionId: token.thresholdSessionId,
      prfFirstB64u: args.auth.passkeyPrfFirstB64u,
      expiresAtMs: args.session.registrationEstablishedSession.expiresAtMs,
      remainingUses: args.session.registrationEstablishedSession.remainingUses,
      ...(persistTransport ? { transport: warmSession.transport } : {}),
    });
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
