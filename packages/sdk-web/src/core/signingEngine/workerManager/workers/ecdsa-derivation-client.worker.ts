import { type WorkerResponseDiagnostics } from '@/core/types/signer-worker';
import initEcdsaDerivationClient, {
  build_ecdsa_role_local_export_artifact_v1,
  RouterAbEcdsaClientCeremonyV1,
} from '../../../../../../../wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.js';
import initEcdsaRegistrationClient, {
  finalize_ecdsa_client_bootstrap_v1,
  open_ecdsa_role_local_signing_share_v1,
  prepare_ecdsa_client_bootstrap_v1,
} from '../../../../../../../wasm/ecdsa_registration_client/pkg/ecdsa_registration_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
  WorkerControlMessage,
  type EcdsaDerivationWorkerOperationType,
} from '../workerTypes';
import {
  isAttachEcdsaDerivationToPresignPort,
  type CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  type CloseRouterAbEcdsaPostRegistrationCeremonyResultV1,
  type CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  type CreateRouterAbEcdsaPostRegistrationCeremonyResultV1,
  type EcdsaDerivationAdditiveShareRequest,
  type EcdsaDerivationAdditiveShareResponse,
  type FinalizeRouterAbEcdsaExplicitExportRequestV1,
  type FinalizeRouterAbEcdsaExplicitExportResultV1,
  type FinalizeRouterAbEcdsaRecoveryActivationRequestV1,
  type FinalizeRouterAbEcdsaRecoveryActivationResultV1,
  type VerifyRouterAbEcdsaRecoveryClientProofsRequestV1,
  type VerifyRouterAbEcdsaRecoveryClientProofsResultV1,
  type VerifyRouterAbEcdsaRefreshClientProofsRequestV1,
  type VerifyRouterAbEcdsaRefreshClientProofsResultV1,
} from '../ecdsaClientWorkerChannels';
import type {
  CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  VerifyRouterAbEcdsaRegistrationClientProofsResultV1,
} from '../../routerAb/ecdsaDerivation/clientCeremony';
import {
  buildRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  parseRouterAbEcdsaDerivationRecoveryRequestV1,
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
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
} from '@/core/signingEngine/session/keyMaterialBrands';
import { IndexedDbEcdsaRoleLocalSessionMaterialStore } from './ecdsaRoleLocalSessionMaterialStore';

const ecdsaDerivationClientWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_derivation_client_bg.wasm',
  'ECDSA Derivation Client',
);
const ecdsaRegistrationClientWasmUrl = resolveWasmUrl(
  'ecdsa_registration_client_bg.wasm',
  'ECDSA Registration Client',
);
let ecdsaDerivationClientInitPromise: Promise<void> | null = null;
let ecdsaRegistrationClientInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();
let presignPort: MessagePort | null = null;
const DIAGNOSTIC_BREAKDOWN_MAX_DEPTH = 2;
const DIAGNOSTIC_BREAKDOWN_MAX_FIELDS = 64;
type StoredEcdsaRoleLocalSigningMaterial = {
  materialHandle: string;
  stateBlobB64u: string;
  bindingDigest: string;
  activationBinding:
    | {
        kind: 'strict_router_ab_activation_v1';
        lifecycleId: string;
        transcriptDigestB64u: string;
        activationDigestB64u: string;
        activatedAtMs: number;
      }
    | {
      kind: 'runtime_import';
      };
};

const ecdsaRoleLocalSigningMaterialStore = new Map<string, StoredEcdsaRoleLocalSigningMaterial>();
const durableEcdsaRoleLocalMaterialStore =
  new IndexedDbEcdsaRoleLocalSessionMaterialStore();

type ActiveRouterAbEcdsaRegistrationCeremony =
  | {
      kind: 'request_built';
      ceremony: RouterAbEcdsaClientCeremonyV1;
      registration: RouterAbEcdsaRegistrationRequestFactsV1;
      registrationRequest: RouterAbEcdsaRegistrationRequestV1;
    }
  | {
      kind: 'client_proofs_verified';
      ceremony: RouterAbEcdsaClientCeremonyV1;
      registration: RouterAbEcdsaRegistrationRequestFactsV1;
      registrationRequest: RouterAbEcdsaRegistrationRequestV1;
      activationFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
      preparedClientBootstrap: WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult;
    };

const routerAbEcdsaRegistrationCeremonies = new Map<
  string,
  ActiveRouterAbEcdsaRegistrationCeremony
>();
type ActiveRouterAbEcdsaPostRegistrationCeremony =
  | {
      kind: 'explicit_export';
      ceremony: RouterAbEcdsaClientCeremonyV1;
    }
  | {
      kind: 'recovery_request_built';
      ceremony: RouterAbEcdsaClientCeremonyV1;
      publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
      proofBundleTranscriptDigestB64u: string;
    }
  | {
      kind: 'recovery_client_proofs_verified';
      ceremony: RouterAbEcdsaClientCeremonyV1;
      publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
      activationFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
      preparedClientBootstrap: WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult;
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
      clientVerifyingShareB64u: readNonEmptyString(
        publicFacts,
        'clientVerifyingShareB64u',
      ),
    },
  };
}

function invokeRegistrationClientBootstrapFinalizer(
  ceremony: RouterAbEcdsaClientCeremonyV1,
  inputJson: string,
): string {
  const method = Reflect.get(ceremony, 'finalize_registration_client_bootstrap');
  if (typeof method !== 'function') {
    throw new Error(
      'Router A/B ECDSA client WASM is missing registration proof finalization; rebuild WASM',
    );
  }
  const output = Reflect.apply(method, ceremony, [inputJson]);
  if (typeof output !== 'string') {
    throw new Error('Router A/B ECDSA client proof finalization returned invalid JSON');
  }
  return output;
}

function invokeRecoveryClientBootstrapFinalizer(
  ceremony: RouterAbEcdsaClientCeremonyV1,
  inputJson: string,
): string {
  const method = Reflect.get(ceremony, 'finalize_recovery_client_bootstrap');
  if (typeof method !== 'function') {
    throw new Error(
      'Router A/B ECDSA client WASM is missing recovery proof finalization; rebuild WASM',
    );
  }
  const output = Reflect.apply(method, ceremony, [inputJson]);
  if (typeof output !== 'string') {
    throw new Error('Router A/B ECDSA recovery proof finalization returned invalid JSON');
  }
  return output;
}

type ParsedRegistrationClientBootstrapFinalization = {
  preparedClientBootstrap: WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult;
  activationFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
};

function parseClientBootstrapFinalization(
  outputJson: string,
  expectedKind:
    | 'router_ab_ecdsa_registration_client_bootstrap_verified_v1'
    | 'router_ab_ecdsa_recovery_client_bootstrap_verified_v1',
): ParsedRegistrationClientBootstrapFinalization {
  const output = requireRecordPayload(JSON.parse(outputJson));
  requireExactKeys(
    output,
    ['kind', 'preparedClientBootstrap', 'activationFacts'],
    'Router A/B ECDSA client proof finalization result',
  );
  if (output.kind !== expectedKind) {
    throw new Error('Router A/B ECDSA client proof finalization result kind is invalid');
  }
  return {
    preparedClientBootstrap: parsePreparedClientBootstrap(output.preparedClientBootstrap),
    activationFacts: parseRouterAbEcdsaVerifiedClientActivationFactsV1(
      output.activationFacts,
    ),
  };
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
    routerAbEcdsaRegistrationCeremonies.set(ceremonyId, {
      kind: 'request_built',
      ceremony,
      registration: request.registration,
      registrationRequest,
    });
    return {
      kind: 'router_ab_ecdsa_registration_ceremony_created_v1',
      ceremonyId,
      registrationRequest,
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
  active.ceremony.close();
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
  let finalized: ParsedRegistrationClientBootstrapFinalization;
  try {
    finalized = parseClientBootstrapFinalization(
      invokeRegistrationClientBootstrapFinalizer(
        active.ceremony,
        JSON.stringify({
          clientProofFinalization: request.clientProofFinalization,
        }),
      ),
      'router_ab_ecdsa_registration_client_bootstrap_verified_v1',
    );
  } catch (error: unknown) {
    closeRouterAbEcdsaRegistrationCeremonyState(ceremonyId, active);
    throw error;
  }
  routerAbEcdsaRegistrationCeremonies.set(ceremonyId, {
    kind: 'client_proofs_verified',
    ceremony: active.ceremony,
    registration: active.registration,
    registrationRequest: active.registrationRequest,
    activationFacts: finalized.activationFacts,
    preparedClientBootstrap: finalized.preparedClientBootstrap,
  });
  return {
    kind: 'router_ab_ecdsa_registration_client_proofs_verified_v1',
    ceremonyId,
    clientBootstrap: finalized.preparedClientBootstrap.clientBootstrap,
    publicFacts: finalized.activationFacts,
  };
}

function routerAbEcdsaRegistrationMaterialHandle(ceremonyId: string): string {
  return `router-ab-ecdsa-registration:${ceremonyId}`;
}

function routerAbEcdsaDurableMaterialRef(materialHandle: string): string {
  return materialHandle;
}

type FinalizedEcdsaRoleLocalActivation = {
  roleLocalMaterial: FinalizeRouterAbEcdsaRecoveryActivationResultV1['roleLocalMaterial'];
  publicFacts: FinalizeRouterAbEcdsaRecoveryActivationResultV1['publicFacts'];
};

async function finalizeAndPersistEcdsaRoleLocalActivation(input: {
  preparedClientBootstrap: WasmPrepareThresholdEcdsaDerivationRoleLocalClientBootstrapResult;
  activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  materialHandle: string;
  expiresAtMs: number;
}): Promise<FinalizedEcdsaRoleLocalActivation> {
  const materialHandle = parseEcdsaRoleLocalMaterialHandle(input.materialHandle);
  const durableMaterialRef = parseEcdsaRoleLocalDurableMaterialRef(
    routerAbEcdsaDurableMaterialRef(materialHandle),
  );
  const activation = input.activationReceipt.ecdsa_activation;
  try {
    const finalizedClientBootstrap = requireRecordPayload(
      JSON.parse(
        finalize_ecdsa_client_bootstrap_v1(
          JSON.stringify({
            kind: 'finalize_ecdsa_client_bootstrap_v1',
            pendingStateBlob: input.preparedClientBootstrap.pendingStateBlob,
            relayerPublicIdentity: {
              relayerKeyId: activation.signing_worker.server_id,
              relayerPublicKey33B64u: activation.public_identity.server_public_key33_b64u,
              groupPublicKey33B64u:
                activation.public_identity.threshold_public_key33_b64u,
              ethereumAddress: ethereumAddressFromBase64Url(
                activation.public_identity.ethereum_address20_b64u,
              ),
              relayerShareRetryCounter:
                activation.public_identity.server_share_retry_counter,
            },
          }),
        ),
      ),
    );
    requireExactKeys(
      finalizedClientBootstrap,
      ['stateBlob', 'publicFacts'],
      'Router A/B ECDSA finalized client bootstrap',
    );
    const stateBlob = requireRecordPayload(finalizedClientBootstrap.stateBlob);
    requireExactKeys(
      stateBlob,
      ['kind', 'curve', 'encoding', 'producer', 'stateBlobB64u'],
      'Router A/B ECDSA ready state blob',
    );
    if (
      stateBlob.kind !== 'ecdsa_role_local_state_blob_v1' ||
      stateBlob.curve !== 'secp256k1' ||
      stateBlob.encoding !== 'base64url' ||
      stateBlob.producer !== 'signer_core'
    ) {
      throw new Error('Router A/B ECDSA ready state blob metadata is invalid');
    }
    const publicFacts = requireRecordPayload(finalizedClientBootstrap.publicFacts);
    requireExactKeys(
      publicFacts,
      [
        'contextBinding32B64u',
        'derivationClientSharePublicKey33B64u',
        'clientVerifyingShareB64u',
        'relayerPublicKey33B64u',
        'groupPublicKey33B64u',
        'ethereumAddress',
      ],
      'Router A/B ECDSA ready public facts',
    );
    const bindingDigest = parseEcdsaRoleLocalBindingDigest(
      readNonEmptyString(publicFacts, 'contextBinding32B64u'),
    );
    const stateBlobB64u = readNonEmptyString(stateBlob, 'stateBlobB64u');
    const activationBinding = {
      kind: 'strict_router_ab_activation_v1',
      lifecycleId: input.activationReceipt.lifecycle_id,
      transcriptDigestB64u: base64UrlEncode(
        Uint8Array.from(input.activationReceipt.transcript_digest.bytes),
      ),
      activationDigestB64u: activation.activation_digest_b64u,
      activatedAtMs: activation.activated_at_ms,
    } as const;
    await durableEcdsaRoleLocalMaterialStore.putActive({
      version: 1,
      durableMaterialRef,
      bindingDigest,
      lifecycleId: activationBinding.lifecycleId,
      transcriptDigestB64u: activationBinding.transcriptDigestB64u,
      activationDigestB64u: activationBinding.activationDigestB64u,
      activatedAtMs: activationBinding.activatedAtMs,
      expiresAtMs: input.expiresAtMs,
      stateBlobB64u,
    });
    ecdsaRoleLocalSigningMaterialStore.set(materialHandle, {
      materialHandle,
      bindingDigest,
      stateBlobB64u,
      activationBinding,
    });
    return {
      roleLocalMaterial: {
        kind: 'ecdsa_role_local_worker_handle_v1',
        materialHandle,
        bindingDigest,
        durableMaterialRef,
      },
      publicFacts: {
        contextBinding32B64u: bindingDigest,
        derivationClientSharePublicKey33B64u: readNonEmptyString(
          publicFacts,
          'derivationClientSharePublicKey33B64u',
        ),
        clientVerifyingShareB64u: readNonEmptyString(
          publicFacts,
          'clientVerifyingShareB64u',
        ),
        relayerPublicKey33B64u: readNonEmptyString(
          publicFacts,
          'relayerPublicKey33B64u',
        ),
        groupPublicKey33B64u: readNonEmptyString(
          publicFacts,
          'groupPublicKey33B64u',
        ),
        ethereumAddress: requireEthereumAddress(
          publicFacts.ethereumAddress,
          'ethereumAddress',
        ),
      },
    };
  } catch (error: unknown) {
    ecdsaRoleLocalSigningMaterialStore.delete(materialHandle);
    await durableEcdsaRoleLocalMaterialStore.burn(durableMaterialRef).catch(() => undefined);
    throw error;
  }
}

function assertRegistrationActivationReceiptMatchesCeremony(
  active: Extract<ActiveRouterAbEcdsaRegistrationCeremony, { kind: 'client_proofs_verified' }>,
  request: FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
): void {
  const receipt = request.activationReceipt;
  const activation = receipt.ecdsa_activation;
  const selectedWorker = active.registration.signer_set.selected_server;
  const publicIdentity = activation.public_identity;
  if (
    receipt.activated !== true ||
    receipt.lifecycle_id !== active.registration.lifecycle.lifecycle_id ||
    base64UrlEncode(Uint8Array.from(receipt.transcript_digest.bytes)) !==
      active.activationFacts.proofTranscriptDigestB64u
  ) {
    throw new Error('Router A/B ECDSA activation receipt transcript is not bound to phase 1');
  }
  if (
    activation.context.application_binding_digest_b64u !==
      active.registration.context.application_binding_digest_b64u ||
    activation.activation_epoch !== active.registration.lifecycle.root_share_epoch
  ) {
    throw new Error('Router A/B ECDSA activation receipt context is not bound to registration');
  }
  if (
    activation.signing_worker.server_id !== selectedWorker.server_id ||
    activation.signing_worker.key_epoch !== selectedWorker.key_epoch ||
    activation.signing_worker.recipient_encryption_key !==
      selectedWorker.recipient_encryption_key
  ) {
    throw new Error('Router A/B ECDSA activation receipt changed the selected SigningWorker');
  }
  if (
    publicIdentity.context_binding_b64u !==
      active.activationFacts.contextBinding32B64u ||
    publicIdentity.derivation_client_share_public_key33_b64u !==
      active.activationFacts.derivationClientSharePublicKey33B64u ||
    publicIdentity.client_share_retry_counter !==
      active.activationFacts.clientShareRetryCounter
  ) {
    throw new Error('Router A/B ECDSA activation receipt changed the verified client identity');
  }
  const nowMs = Date.now();
  if (
    activation.activated_at_ms > active.registration.expires_at_ms ||
    activation.activated_at_ms > nowMs + 60_000
  ) {
    throw new Error('Router A/B ECDSA activation receipt timestamp is outside ceremony policy');
  }
}

async function finalizeRouterAbEcdsaRegistrationActivation(
  request: FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
): Promise<FinalizeRouterAbEcdsaRegistrationActivationResultV1> {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'finalize_router_ab_ecdsa_registration_activation_v1') {
    throw new Error('Router A/B ECDSA registration activation command kind is invalid');
  }
  const active = requireActiveRouterAbEcdsaRegistrationCeremony(ceremonyId);
  if (active.kind !== 'client_proofs_verified') {
    throw new Error('Router A/B ECDSA registration activation requires verified client proofs');
  }
  assertRegistrationActivationReceiptMatchesCeremony(active, request);
  try {
    const finalized = await finalizeAndPersistEcdsaRoleLocalActivation({
      preparedClientBootstrap: active.preparedClientBootstrap,
      activationReceipt: request.activationReceipt,
      materialHandle: routerAbEcdsaRegistrationMaterialHandle(ceremonyId),
      expiresAtMs: active.registration.expires_at_ms,
    });
    return {
      kind: 'router_ab_ecdsa_registration_activation_finalized_v1',
      ceremonyId,
      roleLocalMaterial: finalized.roleLocalMaterial,
      publicFacts: finalized.publicFacts,
      publicCapability: buildRouterAbEcdsaDerivationPublicCapabilityV1({
        registrationFacts: active.registration,
        registrationRequest: active.registrationRequest,
        clientActivation: active.activationFacts,
        activationReceipt: request.activationReceipt,
      }),
    };
  } finally {
    closeRouterAbEcdsaRegistrationCeremonyState(ceremonyId, active);
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
      case 'create_router_ab_ecdsa_explicit_export_ceremony_v1':
        result = {
          kind: 'router_ab_ecdsa_explicit_export_ceremony_created_v1',
          ceremonyId,
          request: parseRouterAbEcdsaDerivationExplicitExportRequestV1(
            JSON.parse(
              ceremony.build_explicit_export_request(JSON.stringify(request.request)),
            ),
          ),
        };
        active = { kind: 'explicit_export', ceremony };
        break;
      case 'create_router_ab_ecdsa_recovery_ceremony_v1': {
        const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(
          request.publicCapability,
        );
        const recoveryRequest = parseRouterAbEcdsaDerivationRecoveryRequestV1(
          JSON.parse(ceremony.build_recovery_request(JSON.stringify(request.request))),
        );
        result = {
          kind: 'router_ab_ecdsa_recovery_ceremony_created_v1',
          ceremonyId,
          request: recoveryRequest,
        };
        active = {
          kind: 'recovery_request_built',
          ceremony,
          publicCapability,
          proofBundleTranscriptDigestB64u:
            ceremony.recovery_transcript_digest_b64u(),
        };
        break;
      }
      case 'create_router_ab_ecdsa_activation_refresh_ceremony_v1': {
        const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(
          request.publicCapability,
        );
        result = {
          kind: 'router_ab_ecdsa_activation_refresh_ceremony_created_v1',
          ceremonyId,
          request: parseRouterAbEcdsaDerivationActivationRefreshRequestV1(
            JSON.parse(
              ceremony.build_activation_refresh_request(JSON.stringify(request.request)),
            ),
          ),
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
    const output = requireRecordPayload(
      JSON.parse(
        active.ceremony.finalize_encrypted_proof_bundles(
          JSON.stringify(request.clientProofFinalization),
        ),
      ),
    );
    requireExactKeys(
      output,
      ['kind', 'output32B64u'],
      'Router A/B ECDSA post-registration proof finalization',
    );
    if (output.kind !== 'router_ab_ecdsa_prf_output_v1') {
      throw new Error('Router A/B ECDSA post-registration proof output kind is invalid');
    }
    const materialHandle = request.roleLocalMaterial.materialHandle;
    const bindingDigest = request.roleLocalMaterial.bindingDigest;
    if (!ecdsaRoleLocalSigningMaterialStore.has(materialHandle)) {
      const restored = await durableEcdsaRoleLocalMaterialStore.restoreActive({
        durableMaterialRef: request.roleLocalMaterial.durableMaterialRef,
        expectedBindingDigest: bindingDigest,
        nowMs: Date.now(),
      });
      if (!restored.ok) {
        throw new Error(`ECDSA explicit export material hydration failed: ${restored.reason}`);
      }
      ecdsaRoleLocalSigningMaterialStore.set(materialHandle, {
        materialHandle,
        bindingDigest,
        stateBlobB64u: restored.stateBlobB64u,
        activationBinding: {
          kind: 'strict_router_ab_activation_v1',
          lifecycleId: restored.lifecycleId,
          transcriptDigestB64u: restored.transcriptDigestB64u,
          activationDigestB64u: restored.activationDigestB64u,
          activatedAtMs: restored.activatedAtMs,
        },
      });
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
            serverExportShare32B64u: readNonEmptyString(output, 'output32B64u'),
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

function verifyRouterAbEcdsaRecoveryClientProofs(
  request: VerifyRouterAbEcdsaRecoveryClientProofsRequestV1,
): VerifyRouterAbEcdsaRecoveryClientProofsResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'verify_router_ab_ecdsa_recovery_client_proofs_v1') {
    throw new Error('Router A/B ECDSA recovery proof command kind is invalid');
  }
  const active = requireRouterAbEcdsaPostRegistrationCeremony(ceremonyId);
  if (active.kind !== 'recovery_request_built') {
    throw new Error('Router A/B ECDSA recovery proofs require an active recovery request');
  }
  let finalized: ParsedRegistrationClientBootstrapFinalization;
  try {
    finalized = parseClientBootstrapFinalization(
      invokeRecoveryClientBootstrapFinalizer(
        active.ceremony,
        JSON.stringify({
          clientProofFinalization: request.clientProofFinalization,
          context: {
            applicationBindingDigestB64u:
              active.publicCapability.context.application_binding_digest_b64u,
          },
          registrationRequestDigestB64u:
            active.publicCapability.registration_request_digest_b64u,
          proofBundleTranscriptDigestB64u: active.proofBundleTranscriptDigestB64u,
          activationProofTranscriptDigestB64u:
            active.publicCapability.proof_transcript_digest_b64u,
        }),
      ),
      'router_ab_ecdsa_recovery_client_bootstrap_verified_v1',
    );
    const capabilityIdentity = active.publicCapability.public_identity;
    if (
      finalized.activationFacts.registrationRequestDigestB64u !==
      active.publicCapability.registration_request_digest_b64u
    ) {
      throw new Error('Router A/B ECDSA recovery changed the registration request binding');
    }
    if (
      finalized.activationFacts.proofTranscriptDigestB64u !==
      active.publicCapability.proof_transcript_digest_b64u
    ) {
      throw new Error('Router A/B ECDSA recovery changed the activation proof binding');
    }
    if (
      finalized.activationFacts.contextBinding32B64u !==
      capabilityIdentity.context_binding_b64u
    ) {
      throw new Error('Router A/B ECDSA recovery changed the client context binding');
    }
    if (
      finalized.activationFacts.derivationClientSharePublicKey33B64u !==
      capabilityIdentity.derivation_client_share_public_key33_b64u
    ) {
      throw new Error('Router A/B ECDSA recovery changed the client public share');
    }
    if (
      finalized.activationFacts.clientShareRetryCounter !==
      capabilityIdentity.client_share_retry_counter
    ) {
      throw new Error('Router A/B ECDSA recovery changed the client share retry counter');
    }
    if (finalized.activationFacts.participantId !== 1) {
      throw new Error('Router A/B ECDSA recovery changed the client participant');
    }
  } catch (error: unknown) {
    closeRouterAbEcdsaPostRegistrationCeremonyState(ceremonyId, active);
    throw error;
  }
  routerAbEcdsaPostRegistrationCeremonies.set(ceremonyId, {
    kind: 'recovery_client_proofs_verified',
    ceremony: active.ceremony,
    publicCapability: active.publicCapability,
    activationFacts: finalized.activationFacts,
    preparedClientBootstrap: finalized.preparedClientBootstrap,
  });
  return {
    kind: 'router_ab_ecdsa_recovery_client_proofs_verified_v1',
    ceremonyId,
    clientBootstrap: finalized.preparedClientBootstrap.clientBootstrap,
    publicFacts: finalized.activationFacts,
  };
}

function verifyRouterAbEcdsaRefreshClientProofs(
  request: VerifyRouterAbEcdsaRefreshClientProofsRequestV1,
): VerifyRouterAbEcdsaRefreshClientProofsResultV1 {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'verify_router_ab_ecdsa_refresh_client_proofs_v1') {
    throw new Error('Router A/B ECDSA refresh proof command kind is invalid');
  }
  const active = requireRouterAbEcdsaPostRegistrationCeremony(ceremonyId);
  if (active.kind !== 'activation_refresh') {
    throw new Error('Router A/B ECDSA refresh proofs require an active refresh request');
  }
  try {
    const output = requireRecordPayload(
      JSON.parse(
        active.ceremony.finalize_encrypted_proof_bundles(
          JSON.stringify(request.clientProofFinalization),
        ),
      ),
    );
    requireExactKeys(
      output,
      ['kind', 'output32B64u'],
      'Router A/B ECDSA refresh proof verification',
    );
    if (output.kind !== 'router_ab_ecdsa_prf_output_v1') {
      throw new Error('Router A/B ECDSA refresh proof output kind is invalid');
    }
    readNonEmptyString(output, 'output32B64u');
    return {
      kind: 'router_ab_ecdsa_refresh_client_proofs_verified_v1',
      ceremonyId,
    };
  } finally {
    closeRouterAbEcdsaPostRegistrationCeremonyState(ceremonyId, active);
  }
}

function assertRecoveryActivationReceiptMatchesCeremony(
  active: Extract<
    ActiveRouterAbEcdsaPostRegistrationCeremony,
    { kind: 'recovery_client_proofs_verified' }
  >,
  request: FinalizeRouterAbEcdsaRecoveryActivationRequestV1,
): void {
  const receipt = request.activationReceipt;
  const activation = receipt.ecdsa_activation;
  const capability = active.publicCapability;
  const expectedIdentity = capability.public_identity;
  const actualIdentity = activation.public_identity;
  if (
    receipt.activated !== true ||
    receipt.lifecycle_id !== request.expectedLifecycleId ||
    base64UrlEncode(Uint8Array.from(receipt.transcript_digest.bytes)) !==
      request.expectedTranscriptDigestB64u
  ) {
    throw new Error('Router A/B ECDSA recovery activation receipt changed the refresh binding');
  }
  if (
    activation.context.application_binding_digest_b64u !==
      capability.context.application_binding_digest_b64u ||
    activation.activation_epoch !== request.expectedActivationEpoch
  ) {
    throw new Error('Router A/B ECDSA recovery activation changed the refresh context');
  }
  const selectedWorker = capability.signer_set.selected_server;
  if (
    activation.signing_worker.server_id !== selectedWorker.server_id ||
    activation.signing_worker.key_epoch !== selectedWorker.key_epoch ||
    activation.signing_worker.recipient_encryption_key !==
      selectedWorker.recipient_encryption_key
  ) {
    throw new Error('Router A/B ECDSA recovery activation changed the selected SigningWorker');
  }
  if (
    actualIdentity.context_binding_b64u !== expectedIdentity.context_binding_b64u ||
    actualIdentity.derivation_client_share_public_key33_b64u !==
      expectedIdentity.derivation_client_share_public_key33_b64u ||
    actualIdentity.server_public_key33_b64u !==
      expectedIdentity.server_public_key33_b64u ||
    actualIdentity.threshold_public_key33_b64u !==
      expectedIdentity.threshold_public_key33_b64u ||
    actualIdentity.ethereum_address20_b64u !==
      expectedIdentity.ethereum_address20_b64u ||
    actualIdentity.client_share_retry_counter !==
      expectedIdentity.client_share_retry_counter ||
    actualIdentity.server_share_retry_counter !==
      expectedIdentity.server_share_retry_counter
  ) {
    throw new Error('Router A/B ECDSA recovery activation changed the registered public identity');
  }
  if (
    !Number.isSafeInteger(request.expiresAtMs) ||
    request.expiresAtMs <= Date.now() ||
    activation.activated_at_ms > request.expiresAtMs ||
    activation.activated_at_ms > Date.now() + 60_000
  ) {
    throw new Error('Router A/B ECDSA recovery activation timestamps are outside session policy');
  }
}

function routerAbEcdsaRecoveryMaterialHandle(
  capability: RouterAbEcdsaDerivationPublicCapabilityV1,
  ceremonyId: string,
): string {
  return `router-ab-ecdsa-recovery:${capability.client_id}:${ceremonyId}`;
}

async function finalizeRouterAbEcdsaRecoveryActivation(
  request: FinalizeRouterAbEcdsaRecoveryActivationRequestV1,
): Promise<FinalizeRouterAbEcdsaRecoveryActivationResultV1> {
  const ceremonyId = requireCeremonyId(request.ceremonyId);
  if (request.kind !== 'finalize_router_ab_ecdsa_recovery_activation_v1') {
    throw new Error('Router A/B ECDSA recovery activation command kind is invalid');
  }
  const active = requireRouterAbEcdsaPostRegistrationCeremony(ceremonyId);
  if (active.kind !== 'recovery_client_proofs_verified') {
    throw new Error('Router A/B ECDSA recovery activation requires verified client proofs');
  }
  assertRecoveryActivationReceiptMatchesCeremony(active, request);
  try {
    const finalized = await finalizeAndPersistEcdsaRoleLocalActivation({
      preparedClientBootstrap: active.preparedClientBootstrap,
      activationReceipt: request.activationReceipt,
      materialHandle: routerAbEcdsaRecoveryMaterialHandle(
        active.publicCapability,
        ceremonyId,
      ),
      expiresAtMs: request.expiresAtMs,
    });
    return {
      kind: 'router_ab_ecdsa_recovery_activation_finalized_v1',
      ceremonyId,
      roleLocalMaterial: finalized.roleLocalMaterial,
      publicFacts: finalized.publicFacts,
      publicCapability: active.publicCapability,
    };
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
  request: EcdsaDerivationAdditiveShareRequest,
): Promise<void> {
  if (ecdsaRoleLocalSigningMaterialStore.has(request.materialHandle)) return;
  const restored = await durableEcdsaRoleLocalMaterialStore.restoreActive({
    durableMaterialRef: request.durableMaterialRef,
    expectedBindingDigest: request.expectedBindingDigest,
    nowMs: Date.now(),
  });
  if (!restored.ok) {
    throw new Error(
      `ECDSA role-local active session hydration failed: ${restored.reason}`,
    );
  }
  ecdsaRoleLocalSigningMaterialStore.set(request.materialHandle, {
    materialHandle: request.materialHandle,
    bindingDigest: request.expectedBindingDigest,
    stateBlobB64u: restored.stateBlobB64u,
    activationBinding: {
      kind: 'strict_router_ab_activation_v1',
      lifecycleId: restored.lifecycleId,
      transcriptDigestB64u: restored.transcriptDigestB64u,
      activationDigestB64u: restored.activationDigestB64u,
      activatedAtMs: restored.activatedAtMs,
    },
  });
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
    const startedAt = Date.now();
    await initEcdsaDerivationClient({ module_or_path: ecdsaDerivationClientWasmUrl });
    console.info('[derivation-client-worker]: ECDSA client WASM initialized', {
      durationMs: Date.now() - startedAt,
      wasmUrl: String(ecdsaDerivationClientWasmUrl),
    });
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

async function loadEcdsaRegistrationClientWasm(): Promise<void> {
  try {
    const startedAt = Date.now();
    await initEcdsaRegistrationClient({ module_or_path: ecdsaRegistrationClientWasmUrl });
    console.info('[derivation-client-worker]: ECDSA registration client WASM initialized', {
      durationMs: Date.now() - startedAt,
      wasmUrl: String(ecdsaRegistrationClientWasmUrl),
    });
  } catch (error: unknown) {
    ecdsaRegistrationClientInitPromise = null;
    console.error(
      '[derivation-client-worker]: ECDSA registration client WASM initialization failed:',
      errorLogSummary(error),
    );
    throw new Error(
      `ECDSA registration client WASM initialization failed: ${safeErrorMessage(error)}`,
    );
  }
}

async function initializeEcdsaRegistrationClientWasm(): Promise<void> {
  if (!ecdsaRegistrationClientInitPromise) {
    ecdsaRegistrationClientInitPromise = loadEcdsaRegistrationClientWasm();
  }
  return ecdsaRegistrationClientInitPromise;
}

async function initializeEcdsaDerivationOperationWasm(
  operationType: EcdsaDerivationWorkerOperationType,
): Promise<void> {
  switch (operationType) {
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs:
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRecoveryClientProofs:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRefreshClientProofs:
      await initializeEcdsaDerivationClientWasm();
      return;
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRecoveryActivation:
      await Promise.all([
        initializeEcdsaDerivationClientWasm(),
        initializeEcdsaRegistrationClientWasm(),
      ]);
      return;
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony:
      return;
    case EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap:
      await initializeEcdsaRegistrationClientWasm();
      return;
    case EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact:
      await initializeEcdsaDerivationClientWasm();
      return;
    case EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial:
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
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation:
      return {
        type: EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaRegistrationActivationSuccess,
        payload: await finalizeRouterAbEcdsaRegistrationActivation(
          payload as FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
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
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRecoveryClientProofs:
      return {
        type: EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRecoveryClientProofsSuccess,
        payload: verifyRouterAbEcdsaRecoveryClientProofs(
          payload as VerifyRouterAbEcdsaRecoveryClientProofsRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRefreshClientProofs:
      return {
        type: EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRefreshClientProofsSuccess,
        payload: verifyRouterAbEcdsaRefreshClientProofs(
          payload as VerifyRouterAbEcdsaRefreshClientProofsRequestV1,
        ),
      };
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRecoveryActivation:
      return {
        type: EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaRecoveryActivationSuccess,
        payload: await finalizeRouterAbEcdsaRecoveryActivation(
          payload as FinalizeRouterAbEcdsaRecoveryActivationRequestV1,
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
  }
  requestType satisfies never;
  throw new Error(`Unsupported DERIVATION client request type: ${requestType}`);
}

function parseEcdsaDerivationOperationType(value: unknown): EcdsaDerivationWorkerOperationType {
  switch (value) {
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation:
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport:
    case EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRecoveryClientProofs:
    case EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRecoveryActivation:
    case EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony:
    case EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial:
    case EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap:
    case EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact:
      return value;
    default:
      throw new Error(`Unsupported DERIVATION client request type: ${String(value)}`);
  }
}

async function handleEcdsaDerivationClientMessage(
  data: unknown,
): Promise<EcdsaDerivationWorkerCommandResult> {
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
    console.info('[derivation-client-worker]: request complete', {
      requestId,
      requestType,
      durationMs: roundMs(completedAt - startedAt),
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
    await initializeEcdsaRegistrationClientWasm();
    await restoreEcdsaRoleLocalSigningMaterialForRequest(request);
    const additiveShare32 = openEcdsaRoleLocalAdditiveShare32FromHandle({
      materialHandle: request.materialHandle,
      expectedBindingDigest: request.expectedBindingDigest,
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
