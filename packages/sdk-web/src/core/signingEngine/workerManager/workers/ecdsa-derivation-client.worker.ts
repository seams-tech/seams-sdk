import { type WorkerResponseDiagnostics } from '@/core/types/signer-worker';
import initEcdsaDerivationClient, {
  build_ecdsa_role_local_export_artifact_v1,
  finalize_ecdsa_client_bootstrap_v1,
  open_ecdsa_role_local_signing_share_v1,
  prepare_ecdsa_client_bootstrap_v1,
  sign_ecdsa_wallet_recovery_material_possession_proof_v1,
  RouterAbEcdsaClientCeremonyV1,
} from '../../../../../../../wasm/router_ab_ecdsa_client/pkg/router_ab_ecdsa_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
} from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcCapabilityRuntimeRef,
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { parseWalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { parseRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  parseWalletRecoveryEcdsaPossessionProofV1,
  type WalletRecoveryEcdsaPossessionProofV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
  WorkerControlMessage,
  type EcdsaDerivationWorkerOperationType,
} from '../workerTypes';
import {
  attachRouterAbEcdsaExplicitExportOperationV1,
  isAttachEcdsaDerivationToPresignPort,
  type CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  type CloseRouterAbEcdsaPostRegistrationCeremonyResultV1,
  type CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  type CreateRouterAbEcdsaPostRegistrationCeremonyResultV1,
  type EcdsaDerivationAdditiveShareRequest,
  type EcdsaDerivationAdditiveShareResponse,
  type FinalizeRouterAbEcdsaExplicitExportRequestV1,
  type FinalizeRouterAbEcdsaExplicitExportResultV1,
  projectRouterAbEcdsaExplicitExportRequestForWasmV1,
  type RehydrateEcdsaRoleLocalSigningMaterialRequestV1,
  type RehydrateEcdsaRoleLocalSigningMaterialResultV1,
  type VerifyRouterAbEcdsaPostRegistrationProofsRequestV1,
  type VerifyRouterAbEcdsaPostRegistrationProofsResultV1,
  type SignWalletRecoveryEcdsaMaterialPossessionProofRequestV1,
  type SignWalletRecoveryEcdsaMaterialPossessionProofResultV1,
} from '../ecdsaClientWorkerChannels';
import type {
  CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  PersistInitialCanonicalEcdsaActivationRequestV1,
  PersistInitialCanonicalEcdsaActivationResultV1,
  ReconcileCanonicalEcdsaActivationRequestV1,
  ReconcileCanonicalEcdsaActivationWorkerResultV1,
  VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  VerifyRouterAbEcdsaRegistrationClientProofsResultV1,
} from '../../routerAb/ecdsaDerivation/clientCeremony';
import {
  buildRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  parseRouterAbEcdsaDerivationExplicitExportProtocolRequestV1,
  type RouterAbEcdsaClientProofFinalizationV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult } from '@/core/types/signer-worker';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
  parseEcdsaRoleLocalPersistedMaterialRef,
  parseEcdsaRoleLocalWorkerHandle,
  type EcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';
import { IndexedDbEcdsaCapabilityManifestStore } from '../../../indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  assertInitialEcdsaActivationPlanMatchesVerifiedCeremony,
  buildInitialEcdsaCapabilityActivationPlan,
} from '../../session/material/initialEcdsaCapabilityActivation';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { buildEcdsaRoleLocalPublicFacts } from '../../session/persistence/ecdsaRoleLocalRecords';
import type {
  PreparedEcdsaActivationJournal,
  ServerCommittedEcdsaActivationJournal,
} from '../../session/material/ecdsaCapabilityManifest';
import {
  buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1,
  decodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  encodeRouterAbEcdsaRegistrationPendingFinalizationV1,
} from '../../routerAb/ecdsaDerivation/registrationPendingFinalization';
import { resolveEcdsaCapabilityHydration } from '../../session/material/ecdsaCapabilityHydration';
import type { MpcCapabilityHydrationBlockedReason } from '../../session/material/mpcCapabilityHydration';

const ecdsaDerivationClientWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_client_bg.wasm',
  'ECDSA Derivation Client',
);
let ecdsaDerivationClientInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();
let presignPort: MessagePort | null = null;
const DIAGNOSTIC_BREAKDOWN_MAX_DEPTH = 2;
const DIAGNOSTIC_BREAKDOWN_MAX_FIELDS = 64;
type StoredEcdsaRoleLocalSigningMaterial = {
  readonly materialHandle: string;
  readonly stateBlobB64u: string;
  readonly bindingDigest: string;
} & (
  | {
      readonly materialActivation: MpcMaterialActivationRef;
      readonly activationBinding: {
        kind: 'strict_router_ab_activation_v1';
        lifecycleId: string;
        transcriptDigestB64u: string;
        activationDigestB64u: string;
        activatedAtMs: number;
      };
    }
  | {
      readonly materialActivation?: never;
      readonly activationBinding: {
        kind: 'runtime_import';
      };
    }
);

function buildStoredCanonicalEcdsaRoleLocalSigningMaterial(input: {
  readonly materialHandle: string;
  readonly stateBlobB64u: string;
  readonly bindingDigest: string;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly activationBinding: {
    readonly kind: 'strict_router_ab_activation_v1';
    readonly lifecycleId: string;
    readonly transcriptDigestB64u: string;
    readonly activationDigestB64u: string;
    readonly activatedAtMs: number;
  };
}): StoredEcdsaRoleLocalSigningMaterial {
  return {
    materialHandle: input.materialHandle,
    stateBlobB64u: input.stateBlobB64u,
    bindingDigest: input.bindingDigest,
    materialActivation: input.materialActivation,
    activationBinding: input.activationBinding,
  };
}

const ecdsaRoleLocalSigningMaterialStore = new Map<string, StoredEcdsaRoleLocalSigningMaterial>();
const ecdsaCapabilityManifestStore = new IndexedDbEcdsaCapabilityManifestStore();

type ActiveRouterAbEcdsaRegistrationCeremony =
  | {
      kind: 'request_built';
      ceremony: RouterAbEcdsaClientCeremonyV1;
      registration: RouterAbEcdsaRegistrationRequestFactsV1;
      registrationRequest: RouterAbEcdsaRegistrationRequestV1;
      registrationBinding: RouterAbEcdsaRegistrationBinding;
    }
  | {
      kind: 'wallet_custody_client_proofs_verified';
      registration: RouterAbEcdsaRegistrationRequestFactsV1;
      registrationRequest: RouterAbEcdsaRegistrationRequestV1;
      registrationBinding: RouterAbEcdsaRegistrationBinding;
    };

const routerAbEcdsaRegistrationCeremonies = new Map<
  string,
  ActiveRouterAbEcdsaRegistrationCeremony
>();
type ActiveRouterAbEcdsaPostRegistrationCeremony =
  | {
      kind: 'explicit_export';
      ceremony: RouterAbEcdsaClientCeremonyV1;
      request: ReturnType<typeof parseRouterAbEcdsaDerivationExplicitExportRequestV1>;
      requestDigestB64u: string;
    }
  | {
      kind: 'activation_refresh';
      ceremony: RouterAbEcdsaClientCeremonyV1;
      publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
    };

const routerAbEcdsaPostRegistrationCeremonies = new Map<
  string,
  ActiveRouterAbEcdsaPostRegistrationCeremony
>();

type EcdsaDerivationWorkerResponse = {
  type: EcdsaDerivationClientCustomResponseType;
  payload: unknown;
};

type EcdsaDerivationWorkerCommandResult = EcdsaDerivationWorkerResponse & {
  wasmInitWaitMs: number;
  wasmCallMs: number;
};

function nowMs(): number {
  return performance.now();
}

function roundMs(value: number): number {
  return Math.max(0, Math.round(value));
}

function collectSizeBreakdown(input: {
  value: unknown;
  out: Record<string, number>;
  path: string;
  depth: number;
}): void {
  if (!input.value || typeof input.value !== 'object' || Array.isArray(input.value)) return;
  if (Object.keys(input.out).length >= DIAGNOSTIC_BREAKDOWN_MAX_FIELDS) return;

  for (const [key, entry] of Object.entries(input.value as Record<string, unknown>)) {
    if (Object.keys(input.out).length >= DIAGNOSTIC_BREAKDOWN_MAX_FIELDS) return;
    const fieldPath = input.path ? `${input.path}.${key}` : key;
    if (typeof entry === 'string') {
      input.out[`${fieldPath}Bytes`] = entry.length;
    } else if (Array.isArray(entry)) {
      input.out[`${fieldPath}Count`] = entry.length;
    } else if (input.depth > 0 && entry && typeof entry === 'object') {
      collectSizeBreakdown({
        value: entry,
        out: input.out,
        path: fieldPath,
        depth: input.depth - 1,
      });
    }
  }
}

function sizeBreakdown(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  collectSizeBreakdown({
    value,
    out,
    path: '',
    depth: DIAGNOSTIC_BREAKDOWN_MAX_DEPTH,
  });
  return out;
}

function totalBreakdownBytes(breakdown: Record<string, number>): number {
  return Object.entries(breakdown).reduce(
    (total, [key, value]) => (key.endsWith('Bytes') ? total + value : total),
    0,
  );
}

function readNonEmptyString(record: Record<string, unknown>, key: string): string {
  const parsed = String(record[key] || '').trim();
  if (!parsed) {
    throw new Error(`ECDSA DERIVATION client worker request is missing ${key}`);
  }
  return parsed;
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function secretB64uField(prefix: string): string {
  return `${prefix}B64u`;
}

function requireRecordPayload(payload: unknown): Record<string, unknown> {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('ECDSA DERIVATION client worker request payload must be an object');
  }
  return payload as Record<string, unknown>;
}

function requireCeremonyId(value: unknown): string {
  const ceremonyId = String(value || '').trim();
  if (!ceremonyId) {
    throw new Error('Router A/B ECDSA registration ceremonyId is required');
  }
  return ceremonyId;
}

function requireExactKeys(
  record: Record<string, unknown>,
  expectedKeys: readonly string[],
  label: string,
): void {
  const actualKeys = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (
    actualKeys.length !== expected.length ||
    actualKeys.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} has an invalid field set`);
  }
}

function requireSafeNonNegativeInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return parsed;
}

function requireEthereumAddress(value: unknown, label: string): `0x${string}` {
  const address = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`${label} must be a 20-byte hexadecimal Ethereum address`);
  }
  return address as `0x${string}`;
}

function ethereumAddressFromBase64Url(value: string): `0x${string}` {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 20) {
    throw new Error('Router A/B ECDSA activation Ethereum address must be 20 bytes');
  }
  let hex = '';
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, '0');
  }
  return `0x${hex}`;
}

function parsePreparedClientBootstrap(
  value: unknown,
): WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult {
  const record = requireRecordPayload(value);
  requireExactKeys(
    record,
    ['pendingStateBlob', 'clientBootstrap', 'publicFacts'],
    'Router A/B ECDSA prepared client bootstrap',
  );
  const pendingStateBlob = requireRecordPayload(record.pendingStateBlob);
  requireExactKeys(
    pendingStateBlob,
    ['kind', 'curve', 'encoding', 'producer', 'stateBlobB64u'],
    'Router A/B ECDSA pending state blob',
  );
  if (
    pendingStateBlob.kind !== 'ecdsa_role_local_pending_state_blob_v1' ||
    pendingStateBlob.curve !== 'secp256k1' ||
    pendingStateBlob.encoding !== 'base64url' ||
    pendingStateBlob.producer !== 'signer_core'
  ) {
    throw new Error('Router A/B ECDSA pending state blob metadata is invalid');
  }
  const clientBootstrap = requireRecordPayload(record.clientBootstrap);
  requireExactKeys(
    clientBootstrap,
    [
      'contextBinding32B64u',
      'derivationClientSharePublicKey33B64u',
      'clientShareRetryCounter',
      'participantId',
    ],
    'Router A/B ECDSA client bootstrap',
  );
  if (clientBootstrap.participantId !== 1) {
    throw new Error('Router A/B ECDSA client bootstrap participantId must be 1');
  }
  const publicFacts = requireRecordPayload(record.publicFacts);
  requireExactKeys(
    publicFacts,
    ['derivationClientSharePublicKey33B64u', 'clientVerifyingShareB64u'],
    'Router A/B ECDSA client public facts',
  );
  return {
    pendingStateBlob: {
      kind: 'ecdsa_role_local_pending_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: readNonEmptyString(pendingStateBlob, 'stateBlobB64u'),
    },
    clientBootstrap: {
      contextBinding32B64u: readNonEmptyString(clientBootstrap, 'contextBinding32B64u'),
      derivationClientSharePublicKey33B64u: readNonEmptyString(
        clientBootstrap,
        'derivationClientSharePublicKey33B64u',
      ),
      clientShareRetryCounter: requireSafeNonNegativeInteger(
        clientBootstrap.clientShareRetryCounter,
        'clientShareRetryCounter',
      ),
      participantId: 1,
    },
    publicFacts: {
      derivationClientSharePublicKey33B64u: readNonEmptyString(
        publicFacts,
        'derivationClientSharePublicKey33B64u',
      ),
      clientVerifyingShareB64u: readNonEmptyString(publicFacts, 'clientVerifyingShareB64u'),
    },
  };
}

type RouterAbEcdsaRegistrationBinding = {
  readonly applicationBindingDigestB64u: string;
  readonly requestDigestB64u: string;
  readonly transcriptDigestB64u: string;
};

function parseRouterAbEcdsaRegistrationBinding(
  ceremony: RouterAbEcdsaClientCeremonyV1,
): RouterAbEcdsaRegistrationBinding {
  const output = requireRecordPayload(JSON.parse(ceremony.registration_binding()));
  requireExactKeys(
    output,
    ['applicationBindingDigestB64u', 'requestDigestB64u', 'transcriptDigestB64u'],
    'Router A/B ECDSA registration binding',
  );
  return {
    applicationBindingDigestB64u: readNonEmptyString(output, 'applicationBindingDigestB64u'),
    requestDigestB64u: readNonEmptyString(output, 'requestDigestB64u'),
    transcriptDigestB64u: readNonEmptyString(output, 'transcriptDigestB64u'),
  };
}

function proofTranscriptDigestB64u(input: RouterAbEcdsaClientProofFinalizationV1): string {
  const signerA = input.bundles.signerA.transcriptDigestB64u;
  const signerB = input.bundles.signerB.transcriptDigestB64u;
  if (signerA !== signerB) {
    throw new Error('Router A/B ECDSA client proof bundles bind different transcripts');
  }
  return signerA;
}

function buildRouterAbEcdsaRegistrationWasmInput(
  registration: RouterAbEcdsaRegistrationRequestFactsV1,
): Record<string, unknown> {
  return {
    registration_purpose: registration.registration_purpose,
    context: registration.context,
    lifecycle: registration.lifecycle,
    signer_set: registration.signer_set,
    router_id: registration.router_id,
    client_id: registration.client_id,
    replay_nonce: registration.replay_nonce,
    expires_at_ms: registration.expires_at_ms,
    deriver_recipient_keys: registration.deriver_recipient_keys,
  };
}

function createRouterAbEcdsaRegistrationCeremony(
  request: CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
): CreateRouterAbEcdsaRegistrationCeremonyResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'create_router_ab_ecdsa_registration_ceremony_v1') {
    throw new Error('Router A/B ECDSA registration create command kind is invalid');
  }
  if (routerAbEcdsaRegistrationCeremonies.has(ceremonyId)) {
    throw new Error('Router A/B ECDSA registration ceremony already exists');
  }
  const ceremony = new RouterAbEcdsaClientCeremonyV1();
  try {
    const registrationRequest: RouterAbEcdsaRegistrationRequestV1 =
      parseRouterAbEcdsaRegistrationRequestV1(
        JSON.parse(
          ceremony.build_registration_request(
            JSON.stringify(buildRouterAbEcdsaRegistrationWasmInput(request.registration)),
          ),
        ),
      );
    const registrationBinding = parseRouterAbEcdsaRegistrationBinding(ceremony);
    routerAbEcdsaRegistrationCeremonies.set(ceremonyId, {
      kind: 'request_built',
      ceremony,
      registration: request.registration,
      registrationRequest,
      registrationBinding,
    });
    return {
      kind: 'router_ab_ecdsa_registration_ceremony_created_v1',
      ceremonyId,
      registrationRequest,
      registrationRequestDigestB64u: registrationBinding.requestDigestB64u,
    };
  } catch (error: unknown) {
    ceremony.close();
    throw error;
  }
}

function requireActiveRouterAbEcdsaRegistrationCeremony(
  ceremonyId: string,
): ActiveRouterAbEcdsaRegistrationCeremony {
  const active = routerAbEcdsaRegistrationCeremonies.get(ceremonyId);
  if (!active) {
    throw new Error('Router A/B ECDSA registration ceremony is not active');
  }
  return active;
}

function closeRouterAbEcdsaRegistrationCeremonyState(
  ceremonyId: string,
  active: ActiveRouterAbEcdsaRegistrationCeremony,
): void {
  if ('ceremony' in active) active.ceremony.close();
  routerAbEcdsaRegistrationCeremonies.delete(ceremonyId);
}

function verifyRouterAbEcdsaRegistrationClientProofs(
  request: VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
): VerifyRouterAbEcdsaRegistrationClientProofsResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'verify_router_ab_ecdsa_registration_client_proofs_v1') {
    throw new Error('Router A/B ECDSA registration proof command kind is invalid');
  }
  const active = requireActiveRouterAbEcdsaRegistrationCeremony(ceremonyId);
  if (active.kind !== 'request_built') {
    throw new Error('Router A/B ECDSA registration client proofs were already verified');
  }
  try {
    const proofTranscriptDigest = proofTranscriptDigestB64u(request.clientProofFinalization);
    if (proofTranscriptDigest !== active.registrationBinding.transcriptDigestB64u) {
      throw new Error('Router A/B ECDSA client proof bundles changed the ceremony transcript');
    }
    active.ceremony.verify_encrypted_proof_bundles(JSON.stringify(request.clientProofFinalization));
  } catch (error: unknown) {
    closeRouterAbEcdsaRegistrationCeremonyState(ceremonyId, active);
    throw error;
  }
  const result: VerifyRouterAbEcdsaRegistrationClientProofsResultV1 = {
    kind: 'router_ab_ecdsa_registration_wallet_custody_proofs_verified_v1',
    bootstrapOwner: 'wallet_custody',
    ceremonyId,
    applicationBindingDigestB64u: active.registrationBinding.applicationBindingDigestB64u,
    registrationRequestDigestB64u: active.registrationBinding.requestDigestB64u,
    proofTranscriptDigestB64u: active.registrationBinding.transcriptDigestB64u,
  };
  active.ceremony.close();
  routerAbEcdsaRegistrationCeremonies.set(ceremonyId, {
    kind: 'wallet_custody_client_proofs_verified',
    registration: active.registration,
    registrationRequest: active.registrationRequest,
    registrationBinding: active.registrationBinding,
  });
  return result;
}

function initialCanonicalActivationFailure(input: {
  readonly ceremonyId: string;
  readonly code: Exclude<
    PersistInitialCanonicalEcdsaActivationResultV1,
    { readonly ok: true }
  >['code'];
  readonly message: string;
}): PersistInitialCanonicalEcdsaActivationResultV1 {
  return {
    ok: false,
    kind: 'initial_canonical_ecdsa_activation_persistence_failed_v1',
    ceremonyId: input.ceremonyId,
    code: input.code,
    message: input.message,
  };
}

async function persistInitialCanonicalEcdsaActivation(
  request: PersistInitialCanonicalEcdsaActivationRequestV1,
): Promise<PersistInitialCanonicalEcdsaActivationResultV1> {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'persist_initial_canonical_ecdsa_activation_v1') {
    return initialCanonicalActivationFailure({
      ceremonyId,
      code: 'invalid_activation_plan',
      message: 'Initial canonical ECDSA activation command kind is invalid',
    });
  }
  const active = routerAbEcdsaRegistrationCeremonies.get(ceremonyId);
  if (!active || active.kind !== 'wallet_custody_client_proofs_verified') {
    return initialCanonicalActivationFailure({
      ceremonyId,
      code: 'invalid_ceremony_state',
      message: 'Initial canonical ECDSA activation requires verified client proofs',
    });
  }
  let plan: Awaited<ReturnType<typeof buildInitialEcdsaCapabilityActivationPlan>>;
  let pendingPayloadB64u: string;
  try {
    const clientActivation = request.clientActivation;
    assertInitialEcdsaActivationPlanMatchesVerifiedCeremony({
      ceremonyId,
      planInput: request.planInput,
      clientActivation,
    });
    plan = await buildInitialEcdsaCapabilityActivationPlan(request.planInput);
    pendingPayloadB64u = encodeRouterAbEcdsaRegistrationPendingFinalizationV1(
      buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1({
        runtimePolicyScope: request.planInput.runtimePolicyScope,
        registrationFacts: active.registration,
        registrationRequest: active.registrationRequest,
        clientActivation,
      }),
    );
  } catch (error: unknown) {
    return initialCanonicalActivationFailure({
      ceremonyId,
      code: 'invalid_activation_plan',
      message: safeErrorMessage(error),
    });
  }
  const stored = await ecdsaCapabilityManifestStore.prepareActivation({
    journalId: plan.journalId,
    expectedManifest: plan.expectedManifest,
    expectedGeneration: plan.expectedGeneration,
    activationBinding: plan.activationBinding,
    requestDigest: plan.requestDigest,
    canonicalRequest: plan.canonicalRequest,
    createdAt: plan.createdAt,
    pendingPayloadB64u,
  });
  switch (stored.kind) {
    case 'stored':
      closeRouterAbEcdsaRegistrationCeremonyState(ceremonyId, active);
      return {
        ok: true,
        kind: 'initial_canonical_ecdsa_activation_persisted_v1',
        ceremonyId,
        journalId: plan.journalId,
      };
    case 'exact_record_conflict':
    case 'corrupt':
    case 'persistence_unavailable':
      return initialCanonicalActivationFailure({
        ceremonyId,
        code: stored.kind,
        message: `Initial canonical ECDSA activation persistence returned ${stored.kind}`,
      });
  }
}

type FinalizedEcdsaRoleLocalActivation = {
  roleLocalMaterial: FinalizeRouterAbEcdsaRegistrationActivationResultV1['roleLocalMaterial'];
  publicFacts: FinalizeRouterAbEcdsaRegistrationActivationResultV1['publicFacts'];
  readyStateBlobB64u: string;
  activationBinding: Extract<
    StoredEcdsaRoleLocalSigningMaterial,
    { readonly activationBinding: { readonly kind: 'strict_router_ab_activation_v1' } }
  >['activationBinding'];
};

function finalizeWalletCustodyEcdsaRoleLocalActivation(input: {
  request: FinalizeRouterAbEcdsaRegistrationActivationRequestV1;
  materialHandle: string;
  durableMaterialRef: string;
  bindingDigest: string;
}): FinalizedEcdsaRoleLocalActivation {
  const materialHandle = parseEcdsaRoleLocalMaterialHandle(input.materialHandle);
  const durableMaterialRef = parseEcdsaRoleLocalDurableMaterialRef(input.durableMaterialRef);
  const receipt = input.request.activationReceipt;
  const activation = receipt.ecdsa_activation;
  const facts = input.request.walletCustodyPublicFacts;
  const ethereumAddress = ethereumAddressFromBase64Url(
    activation.public_identity.ethereum_address20_b64u,
  );
  if (
    facts.contextBinding32B64u !== activation.public_identity.context_binding_b64u ||
    facts.derivationClientSharePublicKey33B64u !==
      activation.public_identity.derivation_client_share_public_key33_b64u ||
    facts.relayerPublicKey33B64u !== activation.public_identity.server_public_key33_b64u ||
    facts.groupPublicKey33B64u !== activation.public_identity.threshold_public_key33_b64u ||
    facts.ethereumAddress !== ethereumAddress ||
    facts.clientShareRetryCounter !== activation.public_identity.client_share_retry_counter ||
    facts.relayerShareRetryCounter !== activation.public_identity.server_share_retry_counter
  ) {
    throw new Error('Wallet custody ECDSA material does not match the activation receipt');
  }
  const bindingDigest = parseEcdsaRoleLocalBindingDigest(facts.contextBinding32B64u);
  if (bindingDigest !== parseEcdsaRoleLocalBindingDigest(input.bindingDigest)) {
    throw new Error('Wallet custody ECDSA material changed the persisted binding digest');
  }
  const readyStateBlobB64u = String(input.request.readyStateBlobB64u || '').trim();
  const readyStateBytes = base64UrlDecode(readyStateBlobB64u);
  if (readyStateBytes.length === 0 || base64UrlEncode(readyStateBytes) !== readyStateBlobB64u) {
    throw new Error('Wallet custody ECDSA ready state must be canonical base64url');
  }
  return {
    roleLocalMaterial: {
      kind: 'ecdsa_role_local_worker_handle_v1',
      materialHandle,
      bindingDigest,
      durableMaterialRef,
    },
    publicFacts: {
      contextBinding32B64u: bindingDigest,
      derivationClientSharePublicKey33B64u: facts.derivationClientSharePublicKey33B64u,
      clientVerifyingShareB64u: facts.clientVerifyingShare33B64u,
      relayerPublicKey33B64u: facts.relayerPublicKey33B64u,
      groupPublicKey33B64u: facts.groupPublicKey33B64u,
      ethereumAddress: facts.ethereumAddress,
    },
    readyStateBlobB64u,
    activationBinding: {
      kind: 'strict_router_ab_activation_v1',
      lifecycleId: receipt.lifecycle_id,
      transcriptDigestB64u: base64UrlEncode(Uint8Array.from(receipt.transcript_digest.bytes)),
      activationDigestB64u: activation.activation_digest_b64u,
      activatedAtMs: activation.activated_at_ms,
    },
  };
}

function assertRegistrationActivationReceiptTimestamp(
  expiresAtMs: number,
  receipt: RouterAbEcdsaRegistrationActivationReceiptV1,
): void {
  const activation = receipt.ecdsa_activation;
  const nowMs = Date.now();
  if (activation.activated_at_ms > expiresAtMs || activation.activated_at_ms > nowMs + 60_000) {
    throw new Error('Router A/B ECDSA activation receipt timestamp is outside ceremony policy');
  }
}

function serverCommitFromActivationReceipt(receipt: RouterAbEcdsaRegistrationActivationReceiptV1) {
  return {
    correlationId: receipt.activation_correlation_id,
    activationRequestDigest: parseDigestB64u(
      base64UrlEncode(Uint8Array.from(receipt.activation_request_digest.bytes)),
    ),
    serverGeneration: receipt.server_generation,
    protocolReceipt: receipt,
  };
}

function normalSigningFromActivationReceipt(input: {
  readonly activationBinding: ServerCommittedEcdsaActivationJournal['candidate']['activationBinding'];
  readonly receipt: RouterAbEcdsaRegistrationActivationReceiptV1;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const activation = input.receipt.ecdsa_activation;
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: String(input.activationBinding.signer.walletId),
      ecdsa_threshold_key_id: String(input.activationBinding.roleLocalBinding.ecdsaThresholdKeyId),
      signing_root_id: String(input.activationBinding.signer.signingRootId),
      signing_root_version: String(input.activationBinding.signer.signingRootVersion),
      context: activation.context,
      public_identity: activation.public_identity,
      material_activation: activation.material_activation,
      signing_worker: activation.signing_worker,
      activation_epoch: activation.activation_epoch,
    },
  };
}

async function committedJournalForActivationReceipt(input: {
  journal: PreparedEcdsaActivationJournal | ServerCommittedEcdsaActivationJournal;
  receipt: RouterAbEcdsaRegistrationActivationReceiptV1;
}): Promise<ServerCommittedEcdsaActivationJournal> {
  switch (input.journal.kind) {
    case 'activation_prepared': {
      const recorded = await ecdsaCapabilityManifestStore.recordServerActivation({
        preparedJournal: input.journal,
        serverCommit: serverCommitFromActivationReceipt(input.receipt),
      });
      if (recorded.kind !== 'stored') {
        throw new Error(`Canonical ECDSA server activation commit returned ${recorded.kind}`);
      }
      return recorded.journal;
    }
    case 'server_activation_committed':
      if (
        alphabetizeStringify(
          input.journal.serverActivation.serverActivationReceipt.protocolReceipt,
        ) !== alphabetizeStringify(input.receipt)
      ) {
        throw new Error('Canonical ECDSA activation receipt conflicts with the committed journal');
      }
      return input.journal;
  }
}

async function finalizeRouterAbEcdsaRegistrationActivation(
  request: FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
): Promise<FinalizeRouterAbEcdsaRegistrationActivationResultV1> {
  if (request.kind !== 'finalize_router_ab_ecdsa_registration_activation_v1') {
    throw new Error('Router A/B ECDSA registration activation command kind is invalid');
  }
  const journalId = parseCorrelationId(request.journalId);
  const receipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(request.activationReceipt);
  const opened = await ecdsaCapabilityManifestStore.openPreparedActivation(journalId);
  if (opened.kind !== 'found') {
    throw new Error(`Canonical ECDSA activation journal open returned ${opened.kind}`);
  }
  const pending = decodeRouterAbEcdsaRegistrationPendingFinalizationV1(opened.pendingPayloadB64u);
  assertRegistrationActivationReceiptTimestamp(pending.registrationFacts.expires_at_ms, receipt);
  const publicCapability = buildRouterAbEcdsaDerivationPublicCapabilityV1({
    registrationFacts: pending.registrationFacts,
    registrationRequest: pending.registrationRequest,
    clientActivation: pending.clientActivation,
    activationReceipt: receipt,
  });
  const committedJournal = await committedJournalForActivationReceipt({
    journal: opened.journal,
    receipt,
  });
  const activationBinding = committedJournal.candidate.activationBinding;
  const materialHandle = parseEcdsaRoleLocalMaterialHandle(activationBinding.durableMaterialRef);
  const finalized = finalizeWalletCustodyEcdsaRoleLocalActivation({
    request,
    materialHandle,
    durableMaterialRef: activationBinding.durableMaterialRef,
    bindingDigest: activationBinding.bindingDigest,
  });
  if (
    finalized.publicFacts.derivationClientSharePublicKey33B64u !==
    activationBinding.roleLocalBinding.clientVerifyingPublicKey33B64u
  ) {
    throw new Error('Router A/B ECDSA ready state changed the persisted client identity');
  }
  const registeredPublicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(activationBinding.roleLocalBinding.keyHandle),
    publicKeyB64u: finalized.publicFacts.groupPublicKey33B64u,
    participantIds: activationBinding.roleLocalBinding.participantIds,
    thresholdOwnerAddress: finalized.publicFacts.ethereumAddress,
  });
  const [chainTarget] = activationBinding.signer.scope.targetMemberships;
  const roleLocalPublicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: activationBinding.signer.walletId,
    chainTarget,
    keyHandle: activationBinding.roleLocalBinding.keyHandle,
    ecdsaThresholdKeyId: activationBinding.roleLocalBinding.ecdsaThresholdKeyId,
    signingRootId: activationBinding.signer.signingRootId,
    signingRootVersion: activationBinding.signer.signingRootVersion,
    applicationBindingDigestB64u: publicCapability.context.application_binding_digest_b64u,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: activationBinding.roleLocalBinding.participantIds,
    contextBinding32B64u: finalized.publicFacts.contextBinding32B64u,
    derivationClientSharePublicKey33B64u:
      finalized.publicFacts.derivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: finalized.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: finalized.publicFacts.groupPublicKey33B64u,
    ethereumAddress: finalized.publicFacts.ethereumAddress,
    publicCapability,
  });
  const sealed = await ecdsaCapabilityManifestStore.sealAndFinalizeActivation({
    committedJournal,
    readyStateBlobB64u: finalized.readyStateBlobB64u,
    registeredPublicFacts,
    roleLocalPublicFacts,
    routerAbEcdsaDerivationNormalSigning: request.routerAbEcdsaDerivationNormalSigning,
    runtimePolicyScope: pending.runtimePolicyScope,
    committedAt: parseIsoTimestamp(
      new Date(receipt.ecdsa_activation.activated_at_ms).toISOString(),
    ),
  });
  if (sealed.kind !== 'committed') {
    throw new Error(`Canonical ECDSA activation finalization returned ${sealed.kind}`);
  }
  ecdsaRoleLocalSigningMaterialStore.set(
    materialHandle,
    buildStoredCanonicalEcdsaRoleLocalSigningMaterial({
      materialHandle,
      bindingDigest: finalized.roleLocalMaterial.bindingDigest,
      stateBlobB64u: finalized.readyStateBlobB64u,
      materialActivation: sealed.manifest.activation.materialActivation,
      activationBinding: finalized.activationBinding,
    }),
  );
  return {
    kind: 'router_ab_ecdsa_registration_activation_finalized_v1',
    journalId,
    authority: sealed.manifest.signer.authority,
    roleLocalMaterial: finalized.roleLocalMaterial,
    materialActivation: sealed.manifest.activation.materialActivation,
    publicFacts: finalized.publicFacts,
    publicCapability,
  };
}

async function reconcileCanonicalEcdsaActivation(
  request: ReconcileCanonicalEcdsaActivationRequestV1,
): Promise<ReconcileCanonicalEcdsaActivationWorkerResultV1> {
  if (request.kind !== 'reconcile_canonical_ecdsa_activation_v1') {
    throw new Error('Canonical ECDSA activation reconciliation command kind is invalid');
  }
  const discovered = await ecdsaCapabilityManifestStore.discoverActivationJournal({
    capability: request.capability,
    authority: request.authority,
  });
  switch (discovered.kind) {
    case 'missing':
      return { kind: 'canonical_ecdsa_activation_reconciliation_absent_v1' };
    case 'corrupt':
    case 'persistence_unavailable':
      return {
        kind: 'canonical_ecdsa_activation_reconciliation_failed_v1',
        code: discovered.kind,
      };
    case 'found':
      break;
  }
  switch (discovered.journal.kind) {
    case 'activation_prepared':
      return {
        kind: 'canonical_ecdsa_activation_reconciliation_pending_v1',
        journalId: discovered.journal.journalId,
        reason: 'parent_confirmation_and_server_query_required',
        activationCommand: discovered.journal.activationCommand,
      };
    case 'server_activation_committed': {
      const activationReceipt =
        discovered.journal.serverActivation.serverActivationReceipt.protocolReceipt;
      return {
        kind: 'canonical_ecdsa_activation_committed_finalization_required_v1',
        journalId: discovered.journal.journalId,
        activationReceipt,
        routerAbEcdsaDerivationNormalSigning: normalSigningFromActivationReceipt({
          activationBinding: discovered.journal.candidate.activationBinding,
          receipt: activationReceipt,
        }),
      };
    }
  }
}

function closeRouterAbEcdsaRegistrationCeremony(
  request: CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
): CloseRouterAbEcdsaRegistrationCeremonyResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'close_router_ab_ecdsa_registration_ceremony_v1') {
    throw new Error('Router A/B ECDSA registration close command kind is invalid');
  }
  const active = requireActiveRouterAbEcdsaRegistrationCeremony(ceremonyId);
  closeRouterAbEcdsaRegistrationCeremonyState(ceremonyId, active);
  return {
    kind: 'router_ab_ecdsa_registration_ceremony_closed_v1',
    ceremonyId,
  };
}

function createRouterAbEcdsaPostRegistrationCeremony(
  request: CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1,
): CreateRouterAbEcdsaPostRegistrationCeremonyResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (routerAbEcdsaPostRegistrationCeremonies.has(ceremonyId)) {
    throw new Error('Router A/B ECDSA post-registration ceremony already exists');
  }
  const ceremony = new RouterAbEcdsaClientCeremonyV1();
  try {
    let result: CreateRouterAbEcdsaPostRegistrationCeremonyResultV1;
    let active: ActiveRouterAbEcdsaPostRegistrationCeremony;
    switch (request.kind) {
      case 'create_router_ab_ecdsa_explicit_export_ceremony_v1': {
        const protocolRequest = parseRouterAbEcdsaDerivationExplicitExportProtocolRequestV1(
          JSON.parse(
            ceremony.build_explicit_export_request(
              JSON.stringify(projectRouterAbEcdsaExplicitExportRequestForWasmV1(request.request)),
            ),
          ),
        );
        const exportRequest = attachRouterAbEcdsaExplicitExportOperationV1({
          facts: request.request,
          protocolRequest,
        });
        result = {
          kind: 'router_ab_ecdsa_explicit_export_ceremony_created_v1',
          ceremonyId,
          request: exportRequest,
          requestDigestB64u: ceremony.explicit_export_request_digest_b64u(),
        };
        active = {
          kind: 'explicit_export',
          ceremony,
          request: exportRequest,
          requestDigestB64u: result.requestDigestB64u,
        };
        break;
      }
      case 'create_router_ab_ecdsa_activation_refresh_ceremony_v1': {
        const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(
          request.publicCapability,
        );
        const refreshRequest = parseRouterAbEcdsaDerivationActivationRefreshRequestV1(
          JSON.parse(ceremony.build_activation_refresh_request(JSON.stringify(request.request))),
        );
        const refreshCeremony = ceremony as unknown as {
          activation_refresh_request_digest_b64u(): string;
        };
        result = {
          kind: 'router_ab_ecdsa_activation_refresh_ceremony_created_v1',
          ceremonyId,
          request: refreshRequest,
          requestDigestB64u: refreshCeremony.activation_refresh_request_digest_b64u(),
        };
        active = {
          kind: 'activation_refresh',
          ceremony,
          publicCapability,
        };
        break;
      }
      default:
        request satisfies never;
        throw new Error('Router A/B ECDSA post-registration command kind is invalid');
    }
    routerAbEcdsaPostRegistrationCeremonies.set(ceremonyId, active);
    return result;
  } catch (error: unknown) {
    ceremony.close();
    throw error;
  }
}

function requireRouterAbEcdsaPostRegistrationCeremony(
  ceremonyId: string,
): ActiveRouterAbEcdsaPostRegistrationCeremony {
  const active = routerAbEcdsaPostRegistrationCeremonies.get(ceremonyId);
  if (!active) {
    throw new Error('Router A/B ECDSA post-registration ceremony is not active');
  }
  return active;
}

function closeRouterAbEcdsaPostRegistrationCeremonyState(
  ceremonyId: string,
  active: ActiveRouterAbEcdsaPostRegistrationCeremony,
): void {
  active.ceremony.close();
  routerAbEcdsaPostRegistrationCeremonies.delete(ceremonyId);
}

async function finalizeRouterAbEcdsaExplicitExport(
  request: FinalizeRouterAbEcdsaExplicitExportRequestV1,
): Promise<FinalizeRouterAbEcdsaExplicitExportResultV1> {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  const active = requireRouterAbEcdsaPostRegistrationCeremony(ceremonyId);
  if (active.kind !== 'explicit_export') {
    throw new Error('ECDSA explicit export finalization requires an active export ceremony');
  }
  try {
    active.ceremony.verify_encrypted_proof_bundles(JSON.stringify(request.clientProofFinalization));
    const exportBinding = {
      wallet_id: String(request.publicFacts.walletId),
      key_handle: request.publicFacts.keyHandle,
      ecdsa_threshold_key_id: String(request.publicFacts.ecdsaThresholdKeyId),
      signing_root_id: String(request.publicFacts.signingRootId),
      signing_root_version: String(request.publicFacts.signingRootVersion),
      activation_epoch: active.request.lifecycle.root_share_epoch,
      signing_worker_id: active.request.lifecycle.selected_server_id,
      context_binding_b64u: active.request.public_identity.context_binding_b64u,
      threshold_public_key33_b64u: active.request.public_identity.threshold_public_key33_b64u,
      export_request_digest_b64u: active.requestDigestB64u,
      export_authorization_digest_b64u: active.request.export_authorization_digest_b64u,
      export_nonce: active.request.export_nonce,
      authorization_kind: request.authorizationKind,
      authorization_id: request.authorizationId,
      material_activation: request.materialActivation,
      lifecycle_id: active.request.lifecycle.lifecycle_id,
      recipient_identity: active.request.client_id,
      recipient_public_key: active.request.client_ephemeral_public_key,
      expires_at_ms: active.request.expires_at_ms,
    };
    const openedShare = requireRecordPayload(
      JSON.parse(
        active.ceremony.open_signing_worker_export_share(
          JSON.stringify(request.signingWorkerExport),
          JSON.stringify(exportBinding),
        ),
      ),
    );
    requireExactKeys(openedShare, ['serverExportShare32B64u'], 'SigningWorker ECDSA export share');
    const materialHandle = request.roleLocalMaterial.materialHandle;
    const bindingDigest = request.roleLocalMaterial.bindingDigest;
    const restored = await restoreEcdsaRoleLocalSigningMaterialForRequest(
      request.roleLocalMaterialRef,
    );
    if (!restored.ok) {
      throw new Error(`ECDSA explicit export material hydration failed: ${restored.reason}`);
    }
    if (restored.liveHandle.materialHandle !== materialHandle) {
      throw new Error('ECDSA explicit export material handle is not canonical');
    }
    const stored = ecdsaRoleLocalSigningMaterialStore.get(materialHandle);
    if (!stored || stored.bindingDigest !== bindingDigest) {
      throw new Error('ECDSA explicit export role-local material binding mismatch');
    }
    const artifact = requireRecordPayload(
      JSON.parse(
        build_ecdsa_role_local_export_artifact_v1(
          JSON.stringify({
            kind: 'build_ecdsa_role_local_export_artifact_v1',
            algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
            stateBlob: {
              kind: 'ecdsa_role_local_state_blob_v1',
              curve: 'secp256k1',
              encoding: 'base64url',
              producer: 'signer_core',
              stateBlobB64u: stored.stateBlobB64u,
            },
            publicFacts: request.publicFacts,
            serverExportShare32B64u: readNonEmptyString(openedShare, 'serverExportShare32B64u'),
          }),
        ),
      ),
    );
    requireExactKeys(
      artifact,
      ['publicKeyHex', 'privateKeyHex', 'ethereumAddress'],
      'ECDSA explicit export artifact',
    );
    return {
      kind: 'router_ab_ecdsa_explicit_export_finalized_v1',
      ceremonyId,
      artifactKind: 'ecdsa-derivation-secp256k1-export',
      publicKeyHex: readNonEmptyString(artifact, 'publicKeyHex'),
      privateKeyHex: readNonEmptyString(artifact, 'privateKeyHex'),
      ethereumAddress: requireEthereumAddress(
        artifact.ethereumAddress,
        'ECDSA explicit export ethereumAddress',
      ),
    };
  } finally {
    closeRouterAbEcdsaPostRegistrationCeremonyState(ceremonyId, active);
  }
}

function verifyRouterAbEcdsaPostRegistrationProofs(
  request: VerifyRouterAbEcdsaPostRegistrationProofsRequestV1,
): VerifyRouterAbEcdsaPostRegistrationProofsResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'verify_router_ab_ecdsa_post_registration_proofs_v1') {
    throw new Error('Router A/B ECDSA post-registration proof command kind is invalid');
  }
  const active = requireRouterAbEcdsaPostRegistrationCeremony(ceremonyId);
  if (active.kind === 'explicit_export') {
    throw new Error('ECDSA explicit export proofs require export finalization');
  }
  try {
    active.ceremony.verify_encrypted_proof_bundles(JSON.stringify(request.clientProofFinalization));
    return { kind: 'router_ab_ecdsa_activation_refresh_proofs_verified_v1', ceremonyId };
  } finally {
    closeRouterAbEcdsaPostRegistrationCeremonyState(ceremonyId, active);
  }
}

function closeRouterAbEcdsaPostRegistrationCeremony(
  request: CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1,
): CloseRouterAbEcdsaPostRegistrationCeremonyResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  const active = requireRouterAbEcdsaPostRegistrationCeremony(ceremonyId);
  closeRouterAbEcdsaPostRegistrationCeremonyState(ceremonyId, active);
  return {
    kind: 'router_ab_ecdsa_post_registration_ceremony_closed_v1',
    ceremonyId,
  };
}

function storeEcdsaRoleLocalSigningMaterial(payload: unknown): StoredEcdsaRoleLocalSigningMaterial {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const bindingDigest = readNonEmptyString(record, 'bindingDigest');
  const stateBlobRecord = requireRecordPayload(record.stateBlob);
  const stateBlobB64u = readNonEmptyString(stateBlobRecord, 'stateBlobB64u');
  const stored = {
    materialHandle,
    stateBlobB64u,
    bindingDigest,
    activationBinding: {
      kind: 'runtime_import',
    } as const,
  };
  ecdsaRoleLocalSigningMaterialStore.set(materialHandle, stored);
  return stored;
}

function signWalletRecoveryEcdsaMaterialPossessionProof(
  request: SignWalletRecoveryEcdsaMaterialPossessionProofRequestV1,
): SignWalletRecoveryEcdsaMaterialPossessionProofResultV1 {
  if (request.kind !== 'sign_wallet_recovery_ecdsa_material_possession_proof_v1') {
    throw new Error('wallet recovery ECDSA possession proof request kind is invalid');
  }
  const rustChallenge = {
    kind: 'seams_wallet_recovery_ecdsa_existing_material_possession_challenge_v1' as const,
    walletId: request.challenge.walletId,
    reservationId: request.challenge.reservationId,
    replacementId: request.challenge.replacementId,
    keySetId: request.challenge.keySetId,
    keyHandle: request.challenge.keyHandle,
    recordedKeyManifestDigestB64u: request.challenge.recordedKeyManifestDigestB64u,
    publicCapabilityDigestB64u: request.challenge.publicCapabilityDigestB64u,
    authorityRefDigestB64u: request.challenge.authorityRefDigestB64u,
    derivationClientSharePublicKey33B64u: request.challenge.derivationClientSharePublicKey33B64u,
    expectedServerGeneration: request.challenge.expectedServerGeneration,
    serverNonceB64u: request.challenge.serverNonceB64u,
    expiresAtMs: request.challenge.expiresAtMs,
  };
  const output = requireRecordPayload(
    JSON.parse(
      sign_ecdsa_wallet_recovery_material_possession_proof_v1(
        JSON.stringify({
          stateBlobB64u: request.stateBlob.stateBlobB64u,
          challenge: rustChallenge,
        }),
      ),
    ),
  );
  requireExactKeys(
    output,
    [
      'kind',
      'scheme',
      'signature64B64u',
      'challengeDigestB64u',
      'derivationClientSharePublicKey33B64u',
    ],
    'wallet recovery ECDSA possession proof',
  );
  if (output.kind !== 'wallet_recovery_ecdsa_possession_proof_v1') {
    throw new Error('wallet recovery ECDSA possession proof kind changed');
  }
  if (output.scheme !== 'secp256k1_bip340_sha256_v1') {
    throw new Error('wallet recovery ECDSA possession proof scheme changed');
  }
  if (
    output.derivationClientSharePublicKey33B64u !==
    request.challenge.derivationClientSharePublicKey33B64u
  ) {
    throw new Error('wallet recovery ECDSA possession proof changed its client public key');
  }
  const challengeDigestB64u = parseDigestB64u(readNonEmptyString(output, 'challengeDigestB64u'));
  const derivationClientSharePublicKey33B64u = readNonEmptyString(
    output,
    'derivationClientSharePublicKey33B64u',
  );
  const proof: WalletRecoveryEcdsaPossessionProofV1 = parseWalletRecoveryEcdsaPossessionProofV1({
    kind: output.kind,
    scheme: output.scheme,
    signature64B64u: output.signature64B64u,
  });
  return {
    kind: 'ecdsa_wallet_recovery_material_possession_proof_v1',
    proof,
    challengeDigestB64u,
    derivationClientSharePublicKey33B64u,
  };
}

function openEcdsaRoleLocalAdditiveShareFromHandle(payload: unknown): unknown {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const expectedBindingDigest = readNonEmptyString(record, 'expectedBindingDigest');
  const stored = ecdsaRoleLocalSigningMaterialStore.get(materialHandle);
  if (!stored) {
    throw new Error('ECDSA role-local signing material handle is not loaded in this worker');
  }
  if (stored.bindingDigest !== expectedBindingDigest) {
    throw new Error('ECDSA role-local signing material binding mismatch');
  }
  return open_ecdsa_role_local_signing_share_v1({
    stateBlobB64u: stored.stateBlobB64u,
  });
}

function openEcdsaRoleLocalAdditiveShare32FromHandle(payload: unknown): Uint8Array {
  const result = openEcdsaRoleLocalAdditiveShareFromHandle(payload) as {
    signingShare32B64u?: unknown;
  };
  const additiveShare32 = base64UrlDecode(String(result.signingShare32B64u || '').trim());
  if (additiveShare32.length !== 32) {
    zeroizeBytes(additiveShare32);
    throw new Error('ECDSA role-local signing material must decode to 32 bytes');
  }
  return additiveShare32;
}

async function restoreEcdsaRoleLocalSigningMaterialForRequest(
  materialRef: EcdsaRoleLocalPersistedMaterialRef,
): Promise<
  | { readonly ok: true; readonly liveHandle: EcdsaRoleLocalWorkerHandle }
  | {
      readonly ok: false;
      readonly reason: 'missing' | 'expired' | 'binding_mismatch' | 'corrupt';
    }
> {
  const materialHandle = parseEcdsaRoleLocalMaterialHandle(materialRef.durableMaterialRef);
  const loaded = ecdsaRoleLocalSigningMaterialStore.get(materialHandle);
  const lookup = await ecdsaCapabilityManifestStore.lookupByMaterialRef(materialRef);
  const runtime =
    loaded?.materialActivation === undefined
      ? { kind: 'absent' as const }
      : {
          kind: 'live' as const,
          runtime: parseEcdsaRoleLocalRuntimeRef(materialHandle),
          materialActivation: loaded.materialActivation,
        };
  const resolution = resolveEcdsaCapabilityHydration({
    lookup,
    runtime,
  });
  switch (resolution.kind) {
    case 'use_live_runtime':
      if (!loaded || loaded.bindingDigest !== materialRef.bindingDigest) {
        return { ok: false, reason: 'binding_mismatch' };
      }
      return {
        ok: true,
        liveHandle: buildEcdsaRoleLocalWorkerHandle(materialRef, materialHandle),
      };
    case 'blocked':
      if (resolution.reason === 'persistence_unavailable') {
        throw new Error('Canonical ECDSA role-local material persistence is unavailable');
      }
      return {
        ok: false,
        reason: restoreFailureReasonFromHydrationBlock(resolution.reason),
      };
    case 'rehydrate_material_activation':
      break;
    case 'reauthorize_public_anchor':
      return { ok: false, reason: 'expired' };
  }
  if (lookup.kind !== 'active') {
    return { ok: false, reason: 'corrupt' };
  }
  const restored = await ecdsaCapabilityManifestStore.openActiveMaterialLookup(lookup);
  if (restored.kind === 'persistence_unavailable') {
    throw new Error('Canonical ECDSA role-local material persistence is unavailable');
  }
  if (restored.kind !== 'active') {
    return {
      ok: false,
      reason: restoreFailureReasonFromManifestObservation(restored.kind),
    };
  }
  const activationReceipt =
    restored.manifest.activation.serverActivation.serverActivationReceipt.protocolReceipt;
  const activation = activationReceipt.ecdsa_activation;
  ecdsaRoleLocalSigningMaterialStore.set(
    materialHandle,
    buildStoredCanonicalEcdsaRoleLocalSigningMaterial({
      materialHandle,
      bindingDigest: materialRef.bindingDigest,
      stateBlobB64u: restored.readyStateBlobB64u,
      materialActivation: restored.manifest.activation.materialActivation,
      activationBinding: {
        kind: 'strict_router_ab_activation_v1',
        lifecycleId: activationReceipt.lifecycle_id,
        transcriptDigestB64u: base64UrlEncode(
          Uint8Array.from(activationReceipt.transcript_digest.bytes),
        ),
        activationDigestB64u: activation.activation_digest_b64u,
        activatedAtMs: activation.activated_at_ms,
      },
    }),
  );
  return {
    ok: true,
    liveHandle: buildEcdsaRoleLocalWorkerHandle(materialRef, materialHandle),
  };
}

function parseEcdsaRoleLocalRuntimeRef(materialHandle: string) {
  const parsed = parseMpcCapabilityRuntimeRef(`ecdsa-role-local-runtime:${materialHandle}`);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function buildEcdsaRoleLocalWorkerHandle(
  materialRef: EcdsaRoleLocalPersistedMaterialRef,
  materialHandle: ReturnType<typeof parseEcdsaRoleLocalMaterialHandle>,
): EcdsaRoleLocalWorkerHandle {
  return {
    kind: 'ecdsa_role_local_worker_handle_v1',
    materialHandle,
    bindingDigest: materialRef.bindingDigest,
    durableMaterialRef: materialRef.durableMaterialRef,
  };
}

function restoreFailureReasonFromHydrationBlock(
  reason: Exclude<MpcCapabilityHydrationBlockedReason, 'persistence_unavailable'>,
): 'missing' | 'expired' | 'binding_mismatch' | 'corrupt' {
  switch (reason) {
    case 'missing_capability':
    case 'missing_material':
      return 'missing';
    case 'revoked':
    case 'replaced':
      return 'expired';
    case 'authority_ambiguous':
    case 'binding_mismatch':
      return 'binding_mismatch';
    case 'exact_record_conflict':
    case 'corrupt':
      return 'corrupt';
  }
}

function restoreFailureReasonFromManifestObservation(
  kind: 'missing' | 'retired' | 'exact_binding_mismatch' | 'exact_record_conflict' | 'corrupt',
): 'missing' | 'expired' | 'binding_mismatch' | 'corrupt' {
  switch (kind) {
    case 'missing':
      return 'missing';
    case 'retired':
      return 'expired';
    case 'exact_binding_mismatch':
      return 'binding_mismatch';
    case 'exact_record_conflict':
    case 'corrupt':
      return 'corrupt';
  }
}

async function openEcdsaRoleLocalSigningMaterial(
  request: RehydrateEcdsaRoleLocalSigningMaterialRequestV1,
): Promise<RehydrateEcdsaRoleLocalSigningMaterialResultV1> {
  if (request.kind !== 'open_ecdsa_role_local_signing_material_v1') {
    throw new Error('ECDSA role-local signing material open kind is invalid');
  }
  const authority = parseWalletAuthAuthorityRef(request.authority);
  if (!authority) {
    throw new Error('ECDSA role-local signing material authority is invalid');
  }
  const materialActivationResult = parseMpcMaterialActivationRef(request.materialActivation);
  if (!materialActivationResult.ok) {
    throw new Error(materialActivationResult.error.message);
  }
  const materialActivation = materialActivationResult.value;
  const lookup = await ecdsaCapabilityManifestStore.lookup({
    capability: materialActivation.capability,
    authority,
  });
  if (lookup.kind === 'persistence_unavailable') {
    throw new Error('Canonical ECDSA role-local material persistence is unavailable');
  }
  if (lookup.kind !== 'active') {
    return {
      kind: 'ecdsa_role_local_signing_material_unavailable_v1',
      ok: false,
      reason: restoreFailureReasonFromManifestObservation(lookup.kind),
    };
  }
  if (
    !mpcMaterialActivationRefsEqual(
      materialActivation,
      lookup.manifest.activation.materialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(
      materialActivation,
      lookup.manifest.durableMaterial.materialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(materialActivation, lookup.material.binding.materialActivation)
  ) {
    return {
      kind: 'ecdsa_role_local_signing_material_unavailable_v1',
      ok: false,
      reason: 'binding_mismatch',
    };
  }
  const materialRef = parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: lookup.manifest.durableMaterial.durableMaterialRef,
    bindingDigest: lookup.manifest.durableMaterial.bindingDigest,
    materialActivation,
  });
  const restored = await restoreEcdsaRoleLocalSigningMaterialForRequest(materialRef);
  if (!restored.ok) {
    return {
      kind: 'ecdsa_role_local_signing_material_unavailable_v1',
      ok: false,
      reason: restored.reason,
    };
  }
  return {
    kind: 'ecdsa_role_local_signing_material_opened_v1',
    ok: true,
    liveHandle: restored.liveHandle,
    materialRef,
  };
}

function operationTimingsFromPayload(payload: unknown): Record<string, number> | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const timings = (payload as { timings?: unknown }).timings;
  if (!timings || typeof timings !== 'object' || Array.isArray(timings)) return null;
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(timings)) {
    const numberValue = Number(value);
    if (Number.isFinite(numberValue)) out[key] = roundMs(numberValue);
  }
  return Object.keys(out).length ? out : null;
}

function workerDiagnostics(input: {
  requestType: number;
  queuedAt: number;
  startedAt: number;
  completedAt: number;
  command: EcdsaDerivationWorkerCommandResult;
  requestPayload: unknown;
}): WorkerResponseDiagnostics {
  const requestPayloadBreakdown = sizeBreakdown(input.requestPayload);
  const responsePayloadBreakdown = sizeBreakdown(input.command.payload);
  const wasmOperationTimings = operationTimingsFromPayload(input.command.payload);
  return {
    kind: 'worker_response_diagnostics_v1',
    worker: 'ecdsaDerivationClient',
    requestType: input.requestType,
    queueWaitMs: roundMs(input.startedAt - input.queuedAt),
    wasmInitWaitMs: input.command.wasmInitWaitMs,
    wasmCallMs: input.command.wasmCallMs,
    totalMs: roundMs(input.completedAt - input.queuedAt),
    requestPayloadBytes: totalBreakdownBytes(requestPayloadBreakdown),
    responsePayloadBytes: totalBreakdownBytes(responsePayloadBreakdown),
    requestPayloadBreakdown,
    responsePayloadBreakdown,
    ...(wasmOperationTimings ? { wasmOperationTimings } : {}),
  };
}

function isDerivationWasmInitFailureMessage(message: string): boolean {
  return /derivation client wasm initialization failed|registration client wasm initialization failed|wasm initialization failed|failed to instantiate|module_or_path|webassembly/i.test(
    message,
  );
}

function classifyEcdsaDerivationWorkerFailure(error: unknown): {
  message: string;
  code: string;
  coreCode?: string;
} {
  if (error && typeof error === 'object') {
    const message =
      typeof (error as { message?: unknown }).message === 'string'
        ? String((error as { message?: string }).message).trim()
        : '';
    const code =
      typeof (error as { code?: unknown }).code === 'string'
        ? String((error as { code?: string }).code).trim()
        : '';
    const coreCode =
      typeof (error as { coreCode?: unknown }).coreCode === 'string'
        ? String((error as { coreCode?: string }).coreCode).trim()
        : '';
    const resolvedMessage = message || safeErrorMessage(error);
    if (isDerivationWasmInitFailureMessage(resolvedMessage)) {
      return {
        message: resolvedMessage,
        code: 'WORKER_RUNTIME_ERROR',
        coreCode: 'ECDSA_DERIVATION_WASM_INIT_FAILURE',
      };
    }
    if (code) {
      return {
        message: resolvedMessage,
        code,
        ...(coreCode ? { coreCode } : {}),
      };
    }
    return {
      message: resolvedMessage,
      code: 'SIGNER_CRYPTO_ERROR',
      coreCode: 'ECDSA_DERIVATION_COMMAND_FAILURE',
    };
  }
  const message = safeErrorMessage(error);
  if (isDerivationWasmInitFailureMessage(message)) {
    return {
      message,
      code: 'WORKER_RUNTIME_ERROR',
      coreCode: 'ECDSA_DERIVATION_WASM_INIT_FAILURE',
    };
  }
  return {
    message,
    code: 'SIGNER_CRYPTO_ERROR',
    coreCode: 'ECDSA_DERIVATION_COMMAND_FAILURE',
  };
}

async function loadEcdsaDerivationClientWasm(): Promise<void> {
  try {
    await initEcdsaDerivationClient({ module_or_path: ecdsaDerivationClientWasmUrl });
  } catch (error: unknown) {
    ecdsaDerivationClientInitPromise = null;
    console.error(
      '[derivation-client-worker]: ECDSA client WASM initialization failed:',
      errorLogSummary(error),
    );
    throw new Error(`ECDSA client WASM initialization failed: ${safeErrorMessage(error)}`);
  }
}

async function initializeEcdsaDerivationClientWasm(): Promise<void> {
  if (!ecdsaDerivationClientInitPromise) {
    ecdsaDerivationClientInitPromise = loadEcdsaDerivationClientWasm();
  }
  return ecdsaDerivationClientInitPromise;
}

async function initializeEcdsaDerivationOperationWasm(
  operationType: EcdsaDerivationWorkerOperationType,
): Promise<void> {
  switch (operationType) {
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaPostRegistrationProofs:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs:
    case EcdsaDerivationClientCustomRequestType.PrewarmEcdsaRegistrationCrypto:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation:
    case EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact:
    case EcdsaDerivationClientCustomRequestType.SignWalletRecoveryEcdsaMaterialPossessionProof:
      await initializeEcdsaDerivationClientWasm();
      return;
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.PersistInitialCanonicalEcdsaActivation:
    case EcdsaDerivationClientCustomRequestType.ReconcileCanonicalEcdsaActivation:
      return;
    case EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial:
    case EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial:
      return;
  }
  operationType satisfies never;
}

async function executeEcdsaDerivationRequest(
  requestType: EcdsaDerivationWorkerOperationType,
  payload: unknown,
): Promise<EcdsaDerivationWorkerResponse> {
  switch (requestType) {
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony:
      return {
        type: EcdsaDerivationClientCustomResponseType.CreateRouterAbEcdsaRegistrationCeremonySuccess,
        payload: createRouterAbEcdsaRegistrationCeremony(
          payload as CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs:
      return {
        type: EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRegistrationClientProofsSuccess,
        payload: verifyRouterAbEcdsaRegistrationClientProofs(
          payload as VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.PersistInitialCanonicalEcdsaActivation:
      return {
        type: EcdsaDerivationClientCustomResponseType.PersistInitialCanonicalEcdsaActivationSuccess,
        payload: await persistInitialCanonicalEcdsaActivation(
          payload as PersistInitialCanonicalEcdsaActivationRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation:
      return {
        type: EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaRegistrationActivationSuccess,
        payload: await finalizeRouterAbEcdsaRegistrationActivation(
          payload as FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.ReconcileCanonicalEcdsaActivation:
      return {
        type: EcdsaDerivationClientCustomResponseType.ReconcileCanonicalEcdsaActivationSuccess,
        payload: await reconcileCanonicalEcdsaActivation(
          payload as ReconcileCanonicalEcdsaActivationRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony:
      return {
        type: EcdsaDerivationClientCustomResponseType.CloseRouterAbEcdsaRegistrationCeremonySuccess,
        payload: closeRouterAbEcdsaRegistrationCeremony(
          payload as CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony:
      return {
        type: EcdsaDerivationClientCustomResponseType.CreateRouterAbEcdsaPostRegistrationCeremonySuccess,
        payload: createRouterAbEcdsaPostRegistrationCeremony(
          payload as CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport:
      return {
        type: EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaExplicitExportSuccess,
        payload: await finalizeRouterAbEcdsaExplicitExport(
          payload as FinalizeRouterAbEcdsaExplicitExportRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaPostRegistrationProofs:
      return {
        type: EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaPostRegistrationProofsSuccess,
        payload: verifyRouterAbEcdsaPostRegistrationProofs(
          payload as VerifyRouterAbEcdsaPostRegistrationProofsRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony:
      return {
        type: EcdsaDerivationClientCustomResponseType.CloseRouterAbEcdsaPostRegistrationCeremonySuccess,
        payload: closeRouterAbEcdsaPostRegistrationCeremony(
          payload as CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial: {
      const stored = storeEcdsaRoleLocalSigningMaterial(payload);
      return {
        type: EcdsaDerivationClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess,
        payload: {
          materialHandle: stored.materialHandle,
          bindingDigest: stored.bindingDigest,
        },
      };
    }
    case EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial:
      return {
        type: EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess,
        payload: await openEcdsaRoleLocalSigningMaterial(
          payload as RehydrateEcdsaRoleLocalSigningMaterialRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.SignWalletRecoveryEcdsaMaterialPossessionProof:
      return {
        type: EcdsaDerivationClientCustomResponseType.SignWalletRecoveryEcdsaMaterialPossessionProofSuccess,
        payload: signWalletRecoveryEcdsaMaterialPossessionProof(
          payload as SignWalletRecoveryEcdsaMaterialPossessionProofRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap:
      return {
        type: EcdsaDerivationClientCustomResponseType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess,
        payload: JSON.parse(prepare_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
      };
    case EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap:
      return {
        type: EcdsaDerivationClientCustomResponseType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess,
        payload: JSON.parse(finalize_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
      };
    case EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact:
      return {
        type: EcdsaDerivationClientCustomResponseType.BuildThresholdEcdsaDerivationRoleLocalExportArtifactSuccess,
        payload: JSON.parse(build_ecdsa_role_local_export_artifact_v1(JSON.stringify(payload))),
      };
    case EcdsaDerivationClientCustomRequestType.PrewarmEcdsaRegistrationCrypto:
      throw new Error('ECDSA registration crypto prewarm does not execute an operation');
  }
  requestType satisfies never;
  throw new Error(`Unsupported DERIVATION client request type: ${requestType}`);
}

function parseEcdsaDerivationOperationType(value: unknown): EcdsaDerivationWorkerOperationType {
  switch (value) {
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs:
    case EcdsaDerivationClientCustomRequestType.PersistInitialCanonicalEcdsaActivation:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation:
    case EcdsaDerivationClientCustomRequestType.ReconcileCanonicalEcdsaActivation:
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaPostRegistrationProofs:
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial:
    case EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial:
    case EcdsaDerivationClientCustomRequestType.SignWalletRecoveryEcdsaMaterialPossessionProof:
    case EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact:
      return value;
    default:
      throw new Error(`Unsupported DERIVATION client request type: ${String(value)}`);
  }
}

function isEcdsaRegistrationCryptoPrewarmRequest(value: unknown): boolean {
  return (
    Number((value as { type?: unknown })?.type) ===
    EcdsaDerivationClientCustomRequestType.PrewarmEcdsaRegistrationCrypto
  );
}

async function handleEcdsaDerivationClientMessage(
  data: unknown,
): Promise<EcdsaDerivationWorkerCommandResult> {
  if (isEcdsaRegistrationCryptoPrewarmRequest(data)) {
    const prewarmStartedAt = nowMs();
    await initializeEcdsaDerivationOperationWasm(
      EcdsaDerivationClientCustomRequestType.PrewarmEcdsaRegistrationCrypto,
    );
    const wasmInitWaitMs = roundMs(nowMs() - prewarmStartedAt);
    return {
      type: EcdsaDerivationClientCustomResponseType.PrewarmEcdsaRegistrationCryptoSuccess,
      payload: {
        kind: 'ecdsa_registration_crypto_prewarm_result_v1',
        wasmInitMs: wasmInitWaitMs,
      },
      wasmInitWaitMs,
      wasmCallMs: 0,
    };
  }
  const request = data as { type?: unknown; payload?: unknown };
  const requestType = request?.type;
  const payload = request?.payload;
  const operationType = parseEcdsaDerivationOperationType(requestType);
  const initStartedAt = nowMs();
  await initializeEcdsaDerivationOperationWasm(operationType);
  const wasmInitWaitMs = roundMs(nowMs() - initStartedAt);
  const wasmCallStartedAt = nowMs();

  const response = await executeEcdsaDerivationRequest(operationType, payload);
  return {
    ...response,
    wasmInitWaitMs,
    wasmCallMs: roundMs(nowMs() - wasmCallStartedAt),
  };
}

setTimeout(() => {
  self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

async function processWorkerMessage(event: MessageEvent): Promise<void> {
  const eventData = event.data as EcdsaDerivationClientWorkerRpcRequest & { queuedAtMs?: unknown };
  const requestId = String(eventData.id || '').trim();
  if (!requestId) {
    throw new Error('ECDSA DERIVATION client worker request is missing RPC id');
  }
  const requestType = Number(eventData.type);

  try {
    const startedAt = nowMs();
    assertNoPrfSecretsInSignerPayload(eventData);
    const response = await handleEcdsaDerivationClientMessage(eventData);
    const completedAt = nowMs();
    self.postMessage({
      id: requestId,
      ok: true,
      result: {
        type: response.type,
        payload: response.payload,
        diagnostics: workerDiagnostics({
          requestType,
          queuedAt: Number(eventData.queuedAtMs ?? startedAt),
          startedAt,
          completedAt,
          command: response,
          requestPayload: eventData.payload,
        }),
      },
    });
  } catch (error: unknown) {
    console.error('[derivation-client-worker]: Message processing failed:', errorLogSummary(error));
    const failure = classifyEcdsaDerivationWorkerFailure(error);
    self.postMessage({
      id: requestId,
      ok: false,
      error: failure.message,
      code: failure.code,
      ...(failure.coreCode ? { coreCode: failure.coreCode } : {}),
    });
  }
}

type EcdsaDerivationClientWorkerRpcRequest = {
  id: string;
  type: EcdsaDerivationWorkerOperationType;
  payload: unknown;
};

function sendAdditiveShareFailure(requestId: string, error: unknown): void {
  if (!presignPort) return;
  const response: EcdsaDerivationAdditiveShareResponse = {
    kind: 'ecdsa_derivation_additive_share_result_v1',
    requestId,
    ok: false,
    error: safeErrorMessage(error),
  };
  presignPort.postMessage(response);
}

async function handleAdditiveShareRequest(
  event: MessageEvent<EcdsaDerivationAdditiveShareRequest>,
): Promise<void> {
  if (!presignPort) return;
  const request = event.data;
  if (request.kind !== 'ecdsa_derivation_additive_share_request_v1') return;
  try {
    await initializeEcdsaDerivationClientWasm();
    let expectedBindingDigest: string;
    switch (request.material.kind) {
      case 'persisted': {
        const materialRef = parseEcdsaRoleLocalPersistedMaterialRef(request.material.materialRef);
        const restored = await restoreEcdsaRoleLocalSigningMaterialForRequest(materialRef);
        if (!restored.ok) {
          throw new Error(`ECDSA role-local active session hydration failed: ${restored.reason}`);
        }
        expectedBindingDigest = materialRef.bindingDigest;
        break;
      }
      case 'runtime_loaded':
        expectedBindingDigest = request.material.expectedBindingDigest;
        break;
    }
    const additiveShare32 = openEcdsaRoleLocalAdditiveShare32FromHandle({
      materialHandle: request.materialHandle,
      expectedBindingDigest,
    });
    const shareBuffer = additiveShare32.buffer;
    const response: EcdsaDerivationAdditiveShareResponse = {
      kind: 'ecdsa_derivation_additive_share_result_v1',
      requestId: request.requestId,
      ok: true,
      additiveShare32: shareBuffer,
    };
    presignPort.postMessage(response, [shareBuffer]);
  } catch (error: unknown) {
    sendAdditiveShareFailure(request.requestId, error);
  }
}

function enqueueAdditiveShareRequest(
  event: MessageEvent<EcdsaDerivationAdditiveShareRequest>,
): void {
  void handleAdditiveShareRequest(event);
}

function attachPresignChannel(value: unknown): boolean {
  if (!isAttachEcdsaDerivationToPresignPort(value)) return false;
  presignPort?.close();
  presignPort = value.port;
  presignPort.onmessage = enqueueAdditiveShareRequest;
  presignPort.start();
  return true;
}

self.onmessage = async (
  event: MessageEvent<EcdsaDerivationClientWorkerRpcRequest>,
): Promise<void> => {
  if (attachPresignChannel(event.data)) return;
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[derivation-client-worker]: Ignoring message without request id');
    return;
  }

  const eventType = event.data?.type;
  if (typeof eventType !== 'number') {
    console.warn(
      '[derivation-client-worker]: Ignoring message with invalid non-numeric type:',
      eventType,
    );
    return;
  }

  const queuedAtMs = nowMs();
  const queuedEvent = {
    ...event,
    data: {
      ...event.data,
      queuedAtMs,
    },
  } as MessageEvent<EcdsaDerivationClientWorkerRpcRequest & { queuedAtMs: number }>;
  messageQueue = messageQueue.catch(() => undefined).then(() => processWorkerMessage(queuedEvent));
  await messageQueue;
};

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[derivation-client-worker]: error:', {
    message: safeErrorMessage(typeof message === 'string' ? message : 'Unknown error'),
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: errorLogSummary(error),
  });
};

self.onunhandledrejection = (event) => {
  console.error(
    '[derivation-client-worker]: Unhandled promise rejection:',
    errorLogSummary(event.reason),
  );
  event.preventDefault();
};

function forbiddenSecretFieldsForEcdsaDerivationWorkerRequest(): string[] {
  return [
    'prfOutput',
    'prf_output',
    'prfFirst',
    'prf_first',
    secretB64uField('prfFirst'),
    'prf_first_b64u',
    'prf',
    'nearPrivateKey',
    'privateKey',
    secretB64uField('signingShare32'),
  ];
}

function assertNoPrfSecretsInSignerPayload(data: unknown): void {
  const payload =
    data && typeof data === 'object' ? (data as { payload?: unknown }).payload : undefined;
  if (!payload || typeof payload !== 'object') return;
  const payloadRecord = payload as Record<string, unknown>;
  for (const key of forbiddenSecretFieldsForEcdsaDerivationWorkerRequest()) {
    if (payloadRecord[key] !== undefined) {
      throw new Error(`Forbidden secret field in signer payload: ${key}`);
    }
  }
}
