import {
  WasmActivatedClientV1,
  WasmCustodySeedRecoverySessionV1,
  WasmCustodySeedRegistrationSessionV1,
  WasmCustodyEnvelopeExportSessionV1,
  openWalletCustodyEd25519MaterialV1,
  default as initializeYaoClientWasm,
  type InitInput,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';
import {
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRecoveryActivationReceiptV1,
  parseRouterAbEd25519YaoRecoveryActivationResultV1,
  parseRouterAbEd25519YaoRecoveryStatusV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoExportAdmissionReceiptV1,
  parseRouterAbEd25519YaoExportExecuteRequestV1,
  parseRouterAbEd25519YaoExportResultV1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationPublicReceiptV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoBytes32V1,
  type RouterAbEd25519YaoRecoveryActivationRequestV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRecoveryStatusRequestV1,
  type RouterAbEd25519YaoRecoveryStatusV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoExportAdmissionRequestV1,
  type RouterAbEd25519YaoExportAdmissionReceiptV1,
  type RouterAbEd25519YaoExportExecuteRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { sameRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import {
  createRouterAbTraceContextV1,
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';

type RegistrationAdmissionReceiptV1 =
  RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
type RegistrationExecuteRequestV1 = RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
type RegistrationWireResultV1 = RouterAbEd25519YaoActivationResultV1<'registration'>;
type RecoveryAdmissionReceiptV1 = RouterAbEd25519YaoActivationAdmissionReceiptV1<'recovery'>;
type RecoveryExecuteRequestV1 = RouterAbEd25519YaoActivationExecuteRequestV1<'recovery'>;
type RecoveryWireResultV1 = RouterAbEd25519YaoActivationResultV1<'recovery'>;

export const ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1 =
  'router_ab_ed25519_yao_active_client_v1' as const;

export type RouterAbEd25519YaoRegistrationTransportFailureV1 = {
  ok: false;
  code: 'transport_failed' | 'router_rejected' | 'invalid_router_response';
  status: number;
  message: string;
};

export type RouterAbEd25519YaoRegistrationTransportResultV1 =
  | {
      ok: true;
      value: unknown;
      /**
       * Raw `Server-Timing` header from the Router, when present. Diagnostics
       * only: it is never parsed into lifecycle control flow, and callers must
       * treat it as absent-by-default.
       */
      serverTiming?: string | null;
    }
  | RouterAbEd25519YaoRegistrationTransportFailureV1;

export type RouterAbEd25519YaoRegistrationTransportRequestV1 =
  | {
      kind: 'admit';
      path: typeof ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1;
      body: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    }
  | {
      kind: 'execute';
      path: typeof ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1;
      body: RegistrationExecuteRequestV1;
    };

export interface RouterAbEd25519YaoRegistrationTransportV1 {
  send(
    request: RouterAbEd25519YaoRegistrationTransportRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationTransportResultV1>;
}

export type RouterAbEd25519YaoRecoveryTransportRequestV1 =
  | {
      kind: 'recovery_admit';
      path: typeof ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1;
      body: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
    }
  | {
      kind: 'recovery_execute';
      path: typeof ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1;
      body: RecoveryExecuteRequestV1;
    }
  | {
      kind: 'recovery_activate';
      path: typeof ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1;
      body: RouterAbEd25519YaoRecoveryActivationRequestV1;
    }
  | {
      kind: 'recovery_status';
      path: typeof ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1;
      body: RouterAbEd25519YaoRecoveryStatusRequestV1;
    };

export interface RouterAbEd25519YaoRecoveryTransportV1 {
  send(
    request: RouterAbEd25519YaoRecoveryTransportRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationTransportResultV1>;
}

export type RouterAbEd25519YaoExportTransportRequestV1 =
  | {
      kind: 'export_admit';
      path: typeof ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1;
      body: {
        protocol: RouterAbEd25519YaoExportAdmissionRequestV1;
        authorization: RouterAbEd25519YaoExportFreshAuthorizationV1;
      };
    }
  | {
      kind: 'export_execute';
      path: typeof ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1;
      body: {
        protocol: RouterAbEd25519YaoExportExecuteRequestV1;
      };
    };

export interface RouterAbEd25519YaoExportTransportV1 {
  send(
    request: RouterAbEd25519YaoExportTransportRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationTransportResultV1>;
}

export type RouterAbEd25519YaoExportFreshAuthorizationV1 =
  | {
      kind: 'passkey';
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      providerSubjectId?: never;
    }
  | {
      kind: 'email_otp_factor';
      providerSubjectId: string;
      webauthnAuthentication?: never;
    };

export type RouterAbEd25519YaoExportArtifactV1 = {
  artifactKind: 'near-ed25519-seed-v1';
  publicKey: string;
  privateKey: string;
};

export function buildRouterAbEd25519YaoExportAdmissionBodyV1(args: {
  protocol: RouterAbEd25519YaoExportAdmissionRequestV1;
  authorization: RouterAbEd25519YaoExportFreshAuthorizationV1;
}): Extract<RouterAbEd25519YaoExportTransportRequestV1, { kind: 'export_admit' }>['body'] {
  switch (args.authorization.kind) {
    case 'passkey':
      return {
        protocol: args.protocol,
        authorization: {
          kind: 'passkey',
          webauthnAuthentication:
            redactCredentialExtensionOutputs<WebAuthnAuthenticationCredential>(
              args.authorization.webauthnAuthentication,
            ),
        },
      };
    case 'email_otp_factor':
      return {
        protocol: args.protocol,
        authorization: {
          kind: 'email_otp_factor',
          providerSubjectId: args.authorization.providerSubjectId,
        },
      };
  }
}

export type RouterAbEd25519YaoExportResultClientV1 =
  | { ok: true; artifact: RouterAbEd25519YaoExportArtifactV1 }
  | RouterAbEd25519YaoRegistrationFailureV1;

export type RouterAbEd25519YaoRegistrationFailureV1 = {
  ok: false;
  code:
    | RouterAbEd25519YaoRegistrationTransportFailureV1['code']
    | 'invalid_factor_secret'
    | 'invalid_client_result';
  status: number;
  message: string;
};

export type RouterAbEd25519YaoActiveClientMetadataV1 = {
  kind: typeof ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1;
  scope: RouterAbEd25519YaoRegistrationAdmissionRequestV1['scope'];
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participantIds: readonly [number, number];
  registeredPublicKey: Uint8Array;
  signingWorkerVerifyingShare: Uint8Array;
  stateEpoch: bigint;
  transcript: Uint8Array;
  activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
  materialActivation: MpcMaterialActivationRef;
};

export type RouterAbEd25519YaoSealedLocalMaterialV1 = {
  kind: 'router_ab_ed25519_yao_sealed_local_material_v1';
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

export type RouterAbEd25519YaoSealLocalMaterialInputV1 = {
  ownedPasskeyPrfFirst: Uint8Array;
  binding: Uint8Array;
  nonce: Uint8Array;
};

export type RouterAbEd25519YaoImportLocalMaterialInputV1 = {
  ownedPasskeyPrfFirst: Uint8Array;
  binding: Uint8Array;
  sealed: RouterAbEd25519YaoSealedLocalMaterialV1;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
};

/**
 * Opening the wallet's continuity cache with any enrolled factor.
 *
 * Carries no `binding`, unlike the per-factor inputs above. The seal binding
 * is rebuilt inside wasm from the record's own fields, because it is both
 * HKDF input and AEAD associated data — a caller that assembled it even
 * slightly differently would hold a record that never opens, and the failure
 * would read as a bad factor rather than a bad binding.
 *
 * The factor secret is whatever opened the custody envelope: `PRF.first`, or
 * the Email OTP factor key. Which one is immaterial here, and that is the
 * point of sealing the cache under the custody seed.
 */
export type RouterAbEd25519YaoOpenCustodyCacheInputV1 = {
  ownedFactorSecret: Uint8Array;
  /** The custody envelope, as stored, and its sealed seed. */
  envelope: {
    bindingJson: string;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    aadHash: Uint8Array;
    ciphertextDigest: Uint8Array;
  };
  applicationBindingDigest: Uint8Array;
  sealed: RouterAbEd25519YaoSealedLocalMaterialV1;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
};

export type RouterAbEd25519YaoEmailOtpSealedLocalMaterialV1 = {
  kind: 'router_ab_ed25519_yao_email_otp_sealed_local_material_v1';
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

export type RouterAbEd25519YaoSealEmailOtpLocalMaterialInputV1 = {
  ownedEnrollmentSecret32: Uint8Array;
  binding: Uint8Array;
  nonce: Uint8Array;
};

export type RouterAbEd25519YaoImportEmailOtpLocalMaterialInputV1 = {
  ownedEnrollmentSecret32: Uint8Array;
  binding: Uint8Array;
  sealed: RouterAbEd25519YaoEmailOtpSealedLocalMaterialV1;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
};

export type RouterAbEd25519YaoClientSigningInputV1 = {
  admittedDigest: Uint8Array;
  signingWorkerCommitments: Readonly<{ hiding: string; binding: string }>;
  signingWorkerVerifyingShare: Uint8Array;
};

export type RouterAbEd25519YaoClientSigningShareV1 = {
  clientCommitments: Readonly<{ hiding: string; binding: string }>;
  clientVerifyingShare: Uint8Array;
  clientSignatureShareB64u: string;
};

export type RouterAbEd25519YaoRegistrationResultV1 =
  | {
      ok: true;
      activeClient: RouterAbEd25519YaoSealableActiveClientV1;
      /** Raw Router `Server-Timing` for the execute call. Diagnostics only. */
      routerServerTiming?: string;
      /** Client-observed Yao sub-steps in ms. Diagnostics only. */
      clientTimings?: { admissionMs: number; sessionCreateMs: number };
    }
  | RouterAbEd25519YaoRegistrationFailureV1;

export type RouterAbEd25519YaoRecoveryResultV1 =
  | {
      ok: true;
      activeClient: RouterAbEd25519YaoSealableActiveClientV1;
      activation: RouterAbEd25519YaoRecoveryActivationReceiptV1;
    }
  | RouterAbEd25519YaoRegistrationFailureV1;

export type RouterAbEd25519YaoPreparedRecoveryInputV1 = {
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  factor: RouterAbEd25519YaoCustodySeedV1;
  transport: RouterAbEd25519YaoRecoveryTransportV1;
  entropy: RouterAbEd25519YaoActivationEntropyV1;
};

export type RouterAbEd25519YaoRecoveryStatusResultV1 =
  | { ok: true; status: RouterAbEd25519YaoRecoveryStatusV1 }
  | RouterAbEd25519YaoRegistrationTransportFailureV1;

export type RouterAbEd25519YaoHttpTransportConfigV1 = {
  routerOrigin: string;
  authorization: string;
  fetch: typeof fetch;
  traceContext?: RouterAbTraceContextV1;
};

type ParsedHttpTransportConfigV1 = {
  routerOrigin: string;
  authorization: string;
  fetch: typeof fetch;
  traceContext: RouterAbTraceContextV1;
};

type RouterAbEd25519YaoActiveClientLifecycleV1 =
  | { kind: 'active'; activated: WasmActivatedClientV1 }
  | { kind: 'disposed'; activated?: never };

export type RouterAbEd25519YaoActiveClientStatusV1 = { kind: 'active' } | { kind: 'disposed' };

export interface RouterAbEd25519YaoActiveClientV1 {
  createSigningShare(
    input: RouterAbEd25519YaoClientSigningInputV1,
  ): Promise<RouterAbEd25519YaoClientSigningShareV1>;
  metadata(): RouterAbEd25519YaoActiveClientMetadataV1;
  status(): RouterAbEd25519YaoActiveClientStatusV1;
  dispose(): void;
}

export interface RouterAbEd25519YaoSealableActiveClientV1 extends RouterAbEd25519YaoActiveClientV1 {
  sealLocalMaterial(
    input: RouterAbEd25519YaoSealLocalMaterialInputV1,
  ): RouterAbEd25519YaoSealedLocalMaterialV1;
  sealEmailOtpLocalMaterial(
    input: RouterAbEd25519YaoSealEmailOtpLocalMaterialInputV1,
  ): RouterAbEd25519YaoEmailOtpSealedLocalMaterialV1;
}

const ACTIVE_CLIENT_CONSTRUCTION = Symbol('router-ab-ed25519-yao-active-client-construction');

type RouterAbEd25519YaoActiveClientConstructionV1 = {
  [ACTIVE_CLIENT_CONSTRUCTION]: true;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  activated: WasmActivatedClientV1;
};

function requireBytes32(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    throw new Error(`${label} must contain 32 bytes`);
  }
  return value;
}

function requireBytes12(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== 12) {
    throw new Error(`${label} must contain 12 bytes`);
  }
  return value;
}

export type RouterAbEd25519YaoCustodySeedV1 = {
  kind: 'wallet_custody_seed';
  ownedSeed32: Uint8Array;
};

export type RouterAbEd25519YaoExportSeedInputV1 = {
  request: RouterAbEd25519YaoExportAdmissionRequestV1;
  transport: RouterAbEd25519YaoExportTransportV1;
  custodyEnvelope: {
    factorSecret: Uint8Array;
    bindingJson: string;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    aadHash: Uint8Array;
    ciphertextDigest: Uint8Array;
  };
  authorization: RouterAbEd25519YaoExportFreshAuthorizationV1;
};

type FactorSecretConsumptionResultV1 =
  | { ok: true; value: Uint8Array }
  | RouterAbEd25519YaoRegistrationFailureV1;

function consumeOwnedCustodySeed(
  factor: RouterAbEd25519YaoCustodySeedV1,
): FactorSecretConsumptionResultV1 {
  const owned = factor.ownedSeed32;
  try {
    return { ok: true, value: requireBytes32(owned.slice(), 'wallet custody seed') };
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_factor_secret',
      status: 0,
      message: error instanceof Error ? error.message : String(error),
    };
  } finally {
    owned.fill(0);
  }
}

function reownConsumedCustodySeed(ownedSeed32: Uint8Array): RouterAbEd25519YaoCustodySeedV1 {
  return { kind: 'wallet_custody_seed', ownedSeed32 };
}

type WasmRegistrationSessionV1 = WasmCustodySeedRegistrationSessionV1;

type WasmRecoverySessionV1 = WasmCustodySeedRecoverySessionV1;

type WasmExportSessionV1 = WasmCustodyEnvelopeExportSessionV1;

function createRegistrationSession(args: {
  admission: unknown;
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participantIds: readonly [number, number];
  factor: RouterAbEd25519YaoCustodySeedV1['kind'];
  secret32: Uint8Array;
  entropy: RouterAbEd25519YaoActivationEntropyV1;
}): WasmRegistrationSessionV1 {
  const common = [
    JSON.stringify(args.admission),
    JSON.stringify(args.applicationBinding),
    args.participantIds[0],
    args.participantIds[1],
    args.secret32,
    args.entropy.recipientKeyMaterial,
    args.entropy.deriverASealSeed,
    args.entropy.deriverBSealSeed,
  ] as const;
  return new WasmCustodySeedRegistrationSessionV1(...common);
}

function createRecoverySession(args: {
  admission: unknown;
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participantIds: readonly [number, number];
  factor: RouterAbEd25519YaoCustodySeedV1['kind'];
  secret32: Uint8Array;
  registeredPublicKey: Uint8Array;
  entropy: RouterAbEd25519YaoActivationEntropyV1;
}): WasmRecoverySessionV1 {
  const common = [
    JSON.stringify(args.admission),
    JSON.stringify(args.applicationBinding),
    args.participantIds[0],
    args.participantIds[1],
    args.secret32,
    args.registeredPublicKey,
    args.entropy.recipientKeyMaterial,
    args.entropy.deriverASealSeed,
    args.entropy.deriverBSealSeed,
  ] as const;
  return new WasmCustodySeedRecoverySessionV1(...common);
}

function createExportSession(args: {
  admission: unknown;
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participantIds: readonly [number, number];
  custodyEnvelope: {
    factorSecret: Uint8Array;
    bindingJson: string;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    aadHash: Uint8Array;
    ciphertextDigest: Uint8Array;
  };
  entropy: RouterAbEd25519YaoActivationEntropyV1;
}): WasmExportSessionV1 {
  const common = [
    JSON.stringify(args.admission),
    JSON.stringify(args.applicationBinding),
    args.participantIds[0],
    args.participantIds[1],
    args.custodyEnvelope.factorSecret,
    args.custodyEnvelope.bindingJson,
    args.custodyEnvelope.nonce,
    args.custodyEnvelope.ciphertext,
    args.custodyEnvelope.aadHash,
    args.custodyEnvelope.ciphertextDigest,
    args.entropy.recipientKeyMaterial,
    args.entropy.deriverASealSeed,
    args.entropy.deriverBSealSeed,
  ] as const;
  return new WasmCustodyEnvelopeExportSessionV1(...common);
}

export type RouterAbEd25519YaoActivationEntropyV1 = {
  recipientKeyMaterial: Uint8Array;
  deriverASealSeed: Uint8Array;
  deriverBSealSeed: Uint8Array;
};

export function createRouterAbEd25519YaoActivationEntropyV1(): RouterAbEd25519YaoActivationEntropyV1 {
  return {
    recipientKeyMaterial: randomNonzeroBytes32(),
    deriverASealSeed: randomNonzeroBytes32(),
    deriverBSealSeed: randomNonzeroBytes32(),
  };
}

export function zeroizeRouterAbEd25519YaoActivationEntropyV1(
  entropy: RouterAbEd25519YaoActivationEntropyV1,
): void {
  entropy.recipientKeyMaterial.fill(0);
  entropy.deriverASealSeed.fill(0);
  entropy.deriverBSealSeed.fill(0);
}

function equalBytes(
  left: Uint8Array | readonly number[],
  right: Uint8Array | readonly number[],
): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function assertNever(value: never): never {
  throw new Error(`Unhandled Ed25519 Yao Client lifecycle: ${String(value)}`);
}

type RecoveryContinuationV1 =
  | {
      stage: 'admitted';
      admission: RecoveryAdmissionReceiptV1;
    }
  | {
      stage: 'executed';
      admission: RecoveryAdmissionReceiptV1;
      executionResult: RecoveryWireResultV1;
    }
  | {
      stage: 'promoted';
      admission: RecoveryAdmissionReceiptV1;
      executionResult: RecoveryWireResultV1;
      activation: RouterAbEd25519YaoRecoveryActivationReceiptV1;
    };

function requireActiveRegistration(
  lifecycle: RouterAbEd25519YaoActiveClientLifecycleV1,
): WasmActivatedClientV1 {
  switch (lifecycle.kind) {
    case 'active':
      return lifecycle.activated;
    case 'disposed':
      throw new Error('Ed25519 Yao Client state is disposed');
    default:
      return assertNever(lifecycle);
  }
}

function sealWasmEmailOtpLocalMaterial(input: {
  activated: WasmActivatedClientV1;
  ownedEnrollmentSecret32: Uint8Array;
  binding: Uint8Array;
  nonce: Uint8Array;
}): Uint8Array {
  const method: unknown = Reflect.get(input.activated, 'seal_email_otp_local_material');
  if (typeof method !== 'function') {
    throw new Error('Bundled Ed25519 Yao WASM does not support Email OTP local material sealing');
  }
  const output: unknown = Reflect.apply(method, input.activated, [
    input.ownedEnrollmentSecret32,
    input.binding,
    input.nonce,
  ]);
  if (!(output instanceof Uint8Array)) {
    throw new Error('Ed25519 Yao WASM returned invalid Email OTP sealed material');
  }
  return output;
}

function importWasmEmailOtpLocalMaterial(
  input: RouterAbEd25519YaoImportEmailOtpLocalMaterialInputV1,
): WasmActivatedClientV1 {
  const method: unknown = Reflect.get(WasmActivatedClientV1, 'import_email_otp_local_material');
  if (typeof method !== 'function') {
    throw new Error('Bundled Ed25519 Yao WASM does not support Email OTP local material import');
  }
  const output: unknown = Reflect.apply(method, WasmActivatedClientV1, [
    requireBytes32(input.ownedEnrollmentSecret32, 'Email OTP enrollment secret'),
    input.binding,
    requireBytes12(input.sealed.nonce, 'Email OTP local material nonce'),
    input.sealed.ciphertext,
    input.metadata.registeredPublicKey,
    input.metadata.stateEpoch,
    input.metadata.participantIds[0],
    input.metadata.participantIds[1],
    input.metadata.signingWorkerVerifyingShare,
  ]);
  if (!(output instanceof WasmActivatedClientV1)) {
    throw new Error('Ed25519 Yao WASM returned invalid Email OTP active Client material');
  }
  return output;
}

function randomNonzeroBytes32(): Uint8Array {
  const output = new Uint8Array(32);
  do {
    globalThis.crypto.getRandomValues(output);
  } while (output.every(isZeroByte));
  return output;
}

function isZeroByte(byte: number): boolean {
  return byte === 0;
}

function parseCommitmentsJson(value: string): Readonly<{ hiding: string; binding: string }> {
  const parsed: unknown = JSON.parse(value);
  const record = asRecord(parsed);
  if (!record) {
    throw new Error('Client commitments must be an object');
  }
  if (typeof record.hiding !== 'string' || typeof record.binding !== 'string') {
    throw new Error('Client commitments must contain hiding and binding strings');
  }
  return { hiding: record.hiding, binding: record.binding };
}

function publicReceiptMetadata(
  receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
): Pick<
  RouterAbEd25519YaoActiveClientMetadataV1,
  'signingWorkerVerifyingShare' | 'transcript' | 'materialActivation'
> {
  const wire = receipt.material_activation;
  const materialActivation = parseMpcMaterialActivationRef({
    kind: wire.kind,
    activationId: wire.activation_id,
    capability: wire.capability,
    materialOwner: wire.material_owner,
    keyBinding: wire.key_binding,
    lifecycleBinding: wire.lifecycle_binding,
    signingWorker: wire.signing_worker,
  });
  if (!materialActivation.ok) {
    throw new Error(`Invalid activation material reference: ${materialActivation.error.message}`);
  }
  return {
    signingWorkerVerifyingShare: Uint8Array.from(receipt.signing_worker_verifying_share),
    transcript: Uint8Array.from(receipt.transcript),
    materialActivation: materialActivation.value,
  };
}

function recoveryActivationMatches(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  result: RecoveryWireResultV1,
  activation: RouterAbEd25519YaoRecoveryActivationReceiptV1,
): boolean {
  return (
    JSON.stringify(activation.binding) === JSON.stringify(result.binding) &&
    JSON.stringify(activation.public_receipt) === JSON.stringify(result.public_receipt) &&
    sameRouterAbMpcMaterialActivationRef(
      result.binding.material_activation,
      request.scope.material_activation,
    ) &&
    equalBytes(activation.active_capability_binding, request.replacement_capability_binding) &&
    equalBytes(activation.retired_capability_binding, request.active_capability_binding) &&
    equalBytes(activation.public_receipt.registered_public_key, request.registered_public_key)
  );
}

function activationAdmissionMatchesScope(
  scope: RouterAbEd25519YaoRegistrationAdmissionRequestV1['scope'],
  receipt: RouterAbEd25519YaoActivationAdmissionReceiptV1,
): boolean {
  const lifecycle = receipt.binding.lifecycle;
  return (
    lifecycle.lifecycle_id === scope.lifecycle_id &&
    lifecycle.root_share_epoch === scope.root_share_epoch &&
    lifecycle.account_id === scope.account_id &&
    lifecycle.session_id === scope.threshold_session_id &&
    lifecycle.signer_set_id === scope.signer_set_id &&
    lifecycle.selected_server_id === scope.signing_worker_id &&
    sameRouterAbMpcMaterialActivationRef(
      receipt.binding.material_activation,
      scope.material_activation,
    )
  );
}

function recoveryContinuationFromStatus(
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  status: RouterAbEd25519YaoRecoveryStatusV1,
): { ok: true; value: RecoveryContinuationV1 } | RouterAbEd25519YaoRegistrationTransportFailureV1 {
  if (status.lifecycle_id !== request.scope.lifecycle_id) {
    return {
      ok: false,
      code: 'invalid_router_response',
      status: 0,
      message: 'Router recovery status does not match the requested lifecycle',
    };
  }
  switch (status.stage) {
    case 'missing':
      return {
        ok: false,
        code: 'router_rejected',
        status: 409,
        message: 'Router recovery admission is unavailable',
      };
    case 'admitted':
      if (!activationAdmissionMatchesScope(request.scope, status.admission_receipt)) {
        break;
      }
      return {
        ok: true,
        value: { stage: 'admitted', admission: status.admission_receipt },
      };
    case 'executed':
      if (!activationAdmissionMatchesScope(request.scope, status.admission_receipt)) {
        break;
      }
      return {
        ok: true,
        value: {
          stage: 'executed',
          admission: status.admission_receipt,
          executionResult: status.execution_result,
        },
      };
    case 'promoted':
      if (!activationAdmissionMatchesScope(request.scope, status.admission_receipt)) {
        break;
      }
      return {
        ok: true,
        value: {
          stage: 'promoted',
          admission: status.admission_receipt,
          executionResult: status.execution_result,
          activation: status.activation_receipt,
        },
      };
    default:
      return assertNever(status);
  }
  return {
    ok: false,
    code: 'invalid_router_response',
    status: 0,
    message: 'Router recovery admission does not match the requested lifecycle scope',
  };
}

export async function readRouterAbEd25519YaoRecoveryStatusV1(input: {
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  transport: RouterAbEd25519YaoRecoveryTransportV1;
}): Promise<RouterAbEd25519YaoRecoveryStatusResultV1> {
  const response = await input.transport.send({
    kind: 'recovery_status',
    path: ROUTER_AB_ED25519_YAO_RECOVERY_STATUS_PATH_V1,
    body: {
      kind: 'router_ab_ed25519_yao_recovery_status_request_v1',
      admission: input.request,
    },
  });
  if (!response.ok) return response;
  const parsed = parseRouterAbEd25519YaoRecoveryStatusV1(response.value);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'invalid_router_response',
      status: 0,
      message: parsed.message,
    };
  }
  return { ok: true, status: parsed.value };
}

function exportAdmissionMatchesRequest(
  request: RouterAbEd25519YaoExportAdmissionRequestV1,
  receipt: RouterAbEd25519YaoExportAdmissionReceiptV1,
): boolean {
  const lifecycle = receipt.binding.ceremony.lifecycle;
  return (
    lifecycle.lifecycle_id === request.scope.lifecycle_id &&
    lifecycle.root_share_epoch === request.scope.root_share_epoch &&
    lifecycle.account_id === request.scope.account_id &&
    lifecycle.session_id === request.scope.threshold_session_id &&
    lifecycle.signer_set_id === request.scope.signer_set_id &&
    lifecycle.selected_server_id === request.scope.signing_worker_id &&
    sameRouterAbMpcMaterialActivationRef(
      receipt.binding.ceremony.material_activation,
      request.scope.material_activation,
    ) &&
    receipt.binding.state_epoch === request.state_epoch &&
    equalBytes(receipt.binding.registered_public_key, request.registered_public_key) &&
    equalBytes(receipt.binding.runtime_policy_binding, request.runtime_policy_binding) &&
    equalBytes(receipt.binding.authorization_digest, request.authorization.authorization_digest)
  );
}

async function continuePreparedRecovery(args: {
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  factorKind: RouterAbEd25519YaoCustodySeedV1['kind'];
  factorSecret32: Uint8Array;
  entropy: RouterAbEd25519YaoActivationEntropyV1;
  continuation: RecoveryContinuationV1;
  transport: RouterAbEd25519YaoRecoveryTransportV1;
}): Promise<RouterAbEd25519YaoRecoveryResultV1> {
  let session: WasmRecoverySessionV1;
  try {
    session = createRecoverySession({
      admission: args.continuation.admission,
      applicationBinding: args.request.application_binding,
      participantIds: args.request.participant_ids,
      factor: args.factorKind,
      secret32: args.factorSecret32,
      registeredPublicKey: Uint8Array.from(args.request.registered_public_key),
      entropy: args.entropy,
    });
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_client_result',
      status: 0,
      message: error instanceof Error ? error.message : String(error),
    };
  } finally {
    args.factorSecret32.fill(0);
    zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
  }

  try {
    let result: RecoveryWireResultV1;
    switch (args.continuation.stage) {
      case 'admitted': {
        const executeRequest = parseRouterAbEd25519YaoRecoveryActivationExecuteRequestV1(
          JSON.parse(session.execute_request_json()),
        );
        if (!executeRequest.ok) {
          return {
            ok: false,
            code: 'invalid_client_result',
            status: 0,
            message: executeRequest.message,
          };
        }
        const executeResponse = await args.transport.send({
          kind: 'recovery_execute',
          path: ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
          body: executeRequest.value,
        });
        if (!executeResponse.ok) return executeResponse;
        const parsedResult = parseRouterAbEd25519YaoRecoveryActivationResultV1(
          executeResponse.value,
        );
        if (!parsedResult.ok) {
          return {
            ok: false,
            code: 'invalid_router_response',
            status: 0,
            message: parsedResult.message,
          };
        }
        result = parsedResult.value;
        break;
      }
      case 'executed':
      case 'promoted':
        result = args.continuation.executionResult;
        break;
      default:
        return assertNever(args.continuation);
    }

    const activated = session.complete(JSON.stringify(result));
    try {
      let activation: RouterAbEd25519YaoRecoveryActivationReceiptV1;
      if (args.continuation.stage === 'promoted') {
        activation = args.continuation.activation;
      } else {
        const activationResponse = await args.transport.send({
          kind: 'recovery_activate',
          path: ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
          body: {
            binding: result.binding,
            public_receipt: result.public_receipt,
          },
        });
        if (!activationResponse.ok) {
          activated.free();
          return activationResponse;
        }
        const parsedActivation = parseRouterAbEd25519YaoRecoveryActivationReceiptV1(
          activationResponse.value,
        );
        if (!parsedActivation.ok) {
          activated.free();
          return {
            ok: false,
            code: 'invalid_router_response',
            status: 0,
            message: parsedActivation.message,
          };
        }
        activation = parsedActivation.value;
      }
      if (!recoveryActivationMatches(args.request, result, activation)) {
        activated.free();
        return {
          ok: false,
          code: 'invalid_router_response',
          status: 0,
          message: 'Router recovery activation does not match the verified result',
        };
      }
      const activeClient = createVerifiedActiveClient({
        activated,
        scope: args.request.scope,
        applicationBinding: args.request.application_binding,
        participantIds: args.request.participant_ids,
        result,
        activeCapabilityBinding: activation.active_capability_binding,
      });
      return { ok: true, activeClient, activation };
    } catch (error) {
      activated.free();
      throw error;
    }
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_client_result',
      status: 0,
      message: error instanceof Error ? error.message : String(error),
    };
  } finally {
    session.free();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

function parseExportArtifactJson(value: string): RouterAbEd25519YaoExportArtifactV1 {
  const parsed: unknown = JSON.parse(value);
  const record = asRecord(parsed);
  if (!record) {
    throw new Error('Ed25519 Yao export artifact must be an object');
  }
  const keys = Object.keys(record).sort();
  const expectedKeys = ['artifactKind', 'privateKey', 'publicKey'].sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error('Ed25519 Yao export artifact contains unexpected fields');
  }
  if (
    record.artifactKind !== 'near-ed25519-seed-v1' ||
    typeof record.publicKey !== 'string' ||
    typeof record.privateKey !== 'string' ||
    !record.publicKey.startsWith('ed25519:') ||
    !record.privateKey.startsWith('ed25519:')
  ) {
    throw new Error('Ed25519 Yao export artifact is invalid');
  }
  return {
    artifactKind: 'near-ed25519-seed-v1',
    publicKey: record.publicKey,
    privateKey: record.privateKey,
  };
}

function parseHttpTransportConfig(
  config: RouterAbEd25519YaoHttpTransportConfigV1,
): ParsedHttpTransportConfigV1 {
  const origin = new URL(config.routerOrigin);
  if ((origin.protocol !== 'http:' && origin.protocol !== 'https:') || origin.pathname !== '/') {
    throw new Error('Router origin must be an HTTP origin without a path');
  }
  if (origin.search || origin.hash) throw new Error('Router origin must not contain query or hash');
  if (typeof config.authorization !== 'string' || config.authorization.length === 0) {
    throw new Error('Router authorization is required');
  }
  if (typeof config.fetch !== 'function') throw new Error('Router fetch is required');
  return {
    routerOrigin: origin.origin,
    authorization: config.authorization,
    fetch: config.fetch,
    traceContext: resolveHttpTraceContext(config.traceContext),
  };
}

function resolveHttpTraceContext(
  traceContext: RouterAbTraceContextV1 | undefined,
): RouterAbTraceContextV1 {
  if (!traceContext) return createRouterAbTraceContextV1();
  if (traceContext.kind !== 'router_ab_trace_context_v1') {
    throw new Error('Router trace context kind is invalid');
  }
  const parsed = parseRouterAbTraceContextV1(traceContext.value);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

async function parseHttpResponse(
  response: Response,
): Promise<RouterAbEd25519YaoRegistrationTransportResultV1> {
  const rawServerTiming = response.headers.get('Server-Timing');
  let value: unknown;
  try {
    value = await response.json();
  } catch (error) {
    return {
      ok: false,
      code: 'invalid_router_response',
      status: response.status,
      message: error instanceof Error ? error.message : String(error),
    };
  }
  if (response.ok) {
    const serverTiming = rawServerTiming || resourceServerTiming(response.url);
    return { ok: true, value, ...(serverTiming ? { serverTiming } : {}) };
  }
  return {
    ok: false,
    code: 'router_rejected',
    status: response.status,
    message: JSON.stringify(value),
  };
}

function resourceServerTiming(responseUrl: string): string | null {
  // Dedicated workers may expose cross-origin metrics through Resource Timing
  // even when their Fetch header list omits Server-Timing.
  if (
    !responseUrl ||
    typeof performance === 'undefined' ||
    typeof performance.getEntriesByName !== 'function'
  ) {
    return null;
  }
  const entries = performance.getEntriesByName(responseUrl, 'resource');
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const entry = entries[index];
    if (!entry || entry.entryType !== 'resource') continue;
    const serialized = serializePerformanceServerTiming(Reflect.get(entry, 'serverTiming'));
    if (serialized) return serialized;
  }
  return null;
}

function serializePerformanceServerTiming(value: unknown): string | null {
  if (!Array.isArray(value)) return null;
  const serialized: string[] = [];
  for (const rawMetric of value) {
    if (typeof rawMetric !== 'object' || rawMetric === null) continue;
    const name = String(Reflect.get(rawMetric, 'name') || '').trim();
    const duration = Number(Reflect.get(rawMetric, 'duration'));
    if (!/^[a-z0-9_]+$/.test(name)) continue;
    if (!Number.isFinite(duration) || duration < 0) continue;
    serialized.push(`${name};dur=${duration}`);
  }
  return serialized.length > 0 ? serialized.join(', ') : null;
}

export class RouterAbEd25519YaoHttpActivationTransportV1
  implements
    RouterAbEd25519YaoRegistrationTransportV1,
    RouterAbEd25519YaoRecoveryTransportV1,
    RouterAbEd25519YaoExportTransportV1
{
  private readonly config: ParsedHttpTransportConfigV1;

  constructor(config: RouterAbEd25519YaoHttpTransportConfigV1) {
    this.config = parseHttpTransportConfig(config);
  }

  traceContext(): RouterAbTraceContextV1 {
    return this.config.traceContext;
  }

  async send(
    request:
      | RouterAbEd25519YaoRegistrationTransportRequestV1
      | RouterAbEd25519YaoRecoveryTransportRequestV1
      | RouterAbEd25519YaoExportTransportRequestV1,
  ): Promise<RouterAbEd25519YaoRegistrationTransportResultV1> {
    let response: Response;
    try {
      response = await this.config.fetch.call(
        globalThis,
        new URL(request.path, this.config.routerOrigin),
        {
          method: 'POST',
          headers: {
            authorization: this.config.authorization,
            'content-type': 'application/json',
            [ROUTER_AB_TRACE_ID_HEADER_V1]: this.config.traceContext.value,
          },
          body: JSON.stringify(request.body),
        },
      );
    } catch (error) {
      return {
        ok: false,
        code: 'transport_failed',
        status: 0,
        message: error instanceof Error ? error.message : String(error),
      };
    }
    return parseHttpResponse(response);
  }
}

export class WasmRouterAbEd25519YaoActiveClientV1 implements RouterAbEd25519YaoSealableActiveClientV1 {
  private readonly activeMetadata: RouterAbEd25519YaoActiveClientMetadataV1;
  private lifecycle: RouterAbEd25519YaoActiveClientLifecycleV1;

  constructor(args: RouterAbEd25519YaoActiveClientConstructionV1) {
    if (args[ACTIVE_CLIENT_CONSTRUCTION] !== true) {
      throw new Error('Ed25519 Yao Client state requires verified WASM completion');
    }
    this.activeMetadata = {
      kind: args.metadata.kind,
      scope: {
        lifecycle_id: args.metadata.scope.lifecycle_id,
        root_share_epoch: args.metadata.scope.root_share_epoch,
        account_id: args.metadata.scope.account_id,
        threshold_session_id: args.metadata.scope.threshold_session_id,
        signer_set_id: args.metadata.scope.signer_set_id,
        signing_worker_id: args.metadata.scope.signing_worker_id,
        material_activation: args.metadata.scope.material_activation,
      },
      applicationBinding: {
        wallet_id: args.metadata.applicationBinding.wallet_id,
        near_ed25519_signing_key_id: args.metadata.applicationBinding.near_ed25519_signing_key_id,
        signing_root_id: args.metadata.applicationBinding.signing_root_id,
        key_creation_signer_slot: args.metadata.applicationBinding.key_creation_signer_slot,
      },
      participantIds: [args.metadata.participantIds[0], args.metadata.participantIds[1]],
      registeredPublicKey: args.metadata.registeredPublicKey.slice(),
      signingWorkerVerifyingShare: args.metadata.signingWorkerVerifyingShare.slice(),
      stateEpoch: args.metadata.stateEpoch,
      transcript: args.metadata.transcript.slice(),
      activeCapabilityBinding: [...args.metadata.activeCapabilityBinding],
      materialActivation: args.metadata.materialActivation,
    };
    this.lifecycle = {
      kind: 'active',
      activated: args.activated,
    };
  }

  sealLocalMaterial(
    input: RouterAbEd25519YaoSealLocalMaterialInputV1,
  ): RouterAbEd25519YaoSealedLocalMaterialV1 {
    const activated = requireActiveRegistration(this.lifecycle);
    try {
      return {
        kind: 'router_ab_ed25519_yao_sealed_local_material_v1',
        nonce: input.nonce.slice(),
        ciphertext: activated.seal_local_material(
          requireBytes32(input.ownedPasskeyPrfFirst, 'passkey PRF.first'),
          input.binding,
          input.nonce,
        ),
      };
    } finally {
      input.ownedPasskeyPrfFirst.fill(0);
    }
  }

  sealEmailOtpLocalMaterial(
    input: RouterAbEd25519YaoSealEmailOtpLocalMaterialInputV1,
  ): RouterAbEd25519YaoEmailOtpSealedLocalMaterialV1 {
    const activated = requireActiveRegistration(this.lifecycle);
    try {
      const nonce = requireBytes12(input.nonce, 'Email OTP local material nonce');
      return {
        kind: 'router_ab_ed25519_yao_email_otp_sealed_local_material_v1',
        nonce: nonce.slice(),
        ciphertext: sealWasmEmailOtpLocalMaterial({
          activated,
          ownedEnrollmentSecret32: requireBytes32(
            input.ownedEnrollmentSecret32,
            'Email OTP enrollment secret',
          ),
          binding: input.binding,
          nonce,
        }),
      };
    } finally {
      input.ownedEnrollmentSecret32.fill(0);
    }
  }

  async createSigningShare(
    input: RouterAbEd25519YaoClientSigningInputV1,
  ): Promise<RouterAbEd25519YaoClientSigningShareV1> {
    const activated = requireActiveRegistration(this.lifecycle);
    const admittedDigest = requireBytes32(input.admittedDigest, 'admitted digest');
    const signingWorkerVerifyingShare = requireBytes32(
      input.signingWorkerVerifyingShare,
      'SigningWorker verifying share',
    );
    if (!equalBytes(signingWorkerVerifyingShare, this.activeMetadata.signingWorkerVerifyingShare)) {
      throw new Error('SigningWorker verifying share does not match activated Client state');
    }
    const output = activated.create_signing_share(
      this.activeMetadata.participantIds[0],
      this.activeMetadata.participantIds[1],
      admittedDigest,
      JSON.stringify(input.signingWorkerCommitments),
      signingWorkerVerifyingShare,
    );
    try {
      return {
        clientCommitments: parseCommitmentsJson(output.client_commitments_json()),
        clientVerifyingShare: output.client_verifying_share(),
        clientSignatureShareB64u: output.client_signature_share_b64u(),
      };
    } finally {
      output.free();
    }
  }

  metadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
    return {
      kind: this.activeMetadata.kind,
      scope: {
        lifecycle_id: this.activeMetadata.scope.lifecycle_id,
        root_share_epoch: this.activeMetadata.scope.root_share_epoch,
        account_id: this.activeMetadata.scope.account_id,
        threshold_session_id: this.activeMetadata.scope.threshold_session_id,
        signer_set_id: this.activeMetadata.scope.signer_set_id,
        signing_worker_id: this.activeMetadata.scope.signing_worker_id,
        material_activation: this.activeMetadata.scope.material_activation,
      },
      applicationBinding: {
        wallet_id: this.activeMetadata.applicationBinding.wallet_id,
        near_ed25519_signing_key_id:
          this.activeMetadata.applicationBinding.near_ed25519_signing_key_id,
        signing_root_id: this.activeMetadata.applicationBinding.signing_root_id,
        key_creation_signer_slot: this.activeMetadata.applicationBinding.key_creation_signer_slot,
      },
      participantIds: [
        this.activeMetadata.participantIds[0],
        this.activeMetadata.participantIds[1],
      ],
      registeredPublicKey: this.activeMetadata.registeredPublicKey.slice(),
      signingWorkerVerifyingShare: this.activeMetadata.signingWorkerVerifyingShare.slice(),
      stateEpoch: this.activeMetadata.stateEpoch,
      transcript: this.activeMetadata.transcript.slice(),
      activeCapabilityBinding: [...this.activeMetadata.activeCapabilityBinding],
      materialActivation: this.activeMetadata.materialActivation,
    };
  }

  status(): RouterAbEd25519YaoActiveClientStatusV1 {
    switch (this.lifecycle.kind) {
      case 'active':
        return { kind: 'active' };
      case 'disposed':
        return { kind: 'disposed' };
      default:
        return assertNever(this.lifecycle);
    }
  }

  dispose(): void {
    switch (this.lifecycle.kind) {
      case 'active': {
        const activated = this.lifecycle.activated;
        this.lifecycle = { kind: 'disposed' };
        activated.free();
        return;
      }
      case 'disposed':
        return;
      default:
        return assertNever(this.lifecycle);
    }
  }
}

function createVerifiedActiveClient(input: {
  activated: WasmActivatedClientV1;
  scope: RouterAbEd25519YaoRegistrationAdmissionRequestV1['scope'];
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participantIds: readonly [number, number];
  result: RegistrationWireResultV1 | RecoveryWireResultV1;
  activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
}): WasmRouterAbEd25519YaoActiveClientV1 {
  const receipt = publicReceiptMetadata(input.result.public_receipt);
  return new WasmRouterAbEd25519YaoActiveClientV1({
    [ACTIVE_CLIENT_CONSTRUCTION]: true,
    metadata: {
      kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
      scope: input.scope,
      applicationBinding: input.applicationBinding,
      participantIds: input.participantIds,
      registeredPublicKey: input.activated.registered_public_key(),
      signingWorkerVerifyingShare: receipt.signingWorkerVerifyingShare,
      stateEpoch: input.activated.state_epoch(),
      transcript: receipt.transcript,
      activeCapabilityBinding: [...input.activeCapabilityBinding],
      materialActivation: receipt.materialActivation,
    },
    activated: input.activated,
  });
}

function importVerifiedActiveClient(
  input: RouterAbEd25519YaoImportLocalMaterialInputV1,
): WasmRouterAbEd25519YaoActiveClientV1 {
  let activated: WasmActivatedClientV1 | null = null;
  try {
    activated = WasmActivatedClientV1.import_local_material(
      requireBytes32(input.ownedPasskeyPrfFirst, 'passkey PRF.first'),
      input.binding,
      input.sealed.nonce,
      input.sealed.ciphertext,
      input.metadata.registeredPublicKey,
      input.metadata.stateEpoch,
      input.metadata.participantIds[0],
      input.metadata.participantIds[1],
      input.metadata.signingWorkerVerifyingShare,
    );
    return new WasmRouterAbEd25519YaoActiveClientV1({
      [ACTIVE_CLIENT_CONSTRUCTION]: true,
      metadata: input.metadata,
      activated,
    });
  } catch (error) {
    activated?.free();
    throw error;
  } finally {
    input.ownedPasskeyPrfFirst.fill(0);
  }
}

function importVerifiedEmailOtpActiveClient(
  input: RouterAbEd25519YaoImportEmailOtpLocalMaterialInputV1,
): WasmRouterAbEd25519YaoActiveClientV1 {
  let activated: WasmActivatedClientV1 | null = null;
  try {
    activated = importWasmEmailOtpLocalMaterial(input);
    return new WasmRouterAbEd25519YaoActiveClientV1({
      [ACTIVE_CLIENT_CONSTRUCTION]: true,
      metadata: input.metadata,
      activated,
    });
  } catch (error) {
    activated?.free();
    throw error;
  } finally {
    input.ownedEnrollmentSecret32.fill(0);
  }
}

function openVerifiedCustodyCacheActiveClient(
  input: RouterAbEd25519YaoOpenCustodyCacheInputV1,
): WasmRouterAbEd25519YaoActiveClientV1 {
  let activated: WasmActivatedClientV1 | null = null;
  try {
    activated = openWalletCustodyEd25519MaterialV1(
      input.ownedFactorSecret,
      input.envelope.bindingJson,
      input.envelope.nonce,
      input.envelope.ciphertext,
      input.envelope.aadHash,
      input.envelope.ciphertextDigest,
      input.applicationBindingDigest,
      input.metadata.registeredPublicKey,
      input.metadata.stateEpoch,
      input.metadata.participantIds[0],
      input.metadata.participantIds[1],
      input.metadata.signingWorkerVerifyingShare,
      input.sealed.nonce,
      input.sealed.ciphertext,
    );
    return new WasmRouterAbEd25519YaoActiveClientV1({
      [ACTIVE_CLIENT_CONSTRUCTION]: true,
      metadata: input.metadata,
      activated,
    });
  } catch (error) {
    activated?.free();
    throw error;
  } finally {
    /* Zeroed on every path, like the per-factor importers. The factor secret
       opened the custody envelope moments ago; leaving it in a live buffer
       would outlast the one call it was needed for. */
    input.ownedFactorSecret.fill(0);
  }
}

export class RouterAbEd25519YaoClientV1 {
  private constructor() {}

  static async initializeBundled(): Promise<RouterAbEd25519YaoClientV1> {
    await initializeYaoClientWasm();
    return new RouterAbEd25519YaoClientV1();
  }

  static async initialize(
    moduleOrPath: InitInput | Promise<InitInput>,
  ): Promise<RouterAbEd25519YaoClientV1> {
    await initializeYaoClientWasm({ module_or_path: moduleOrPath });
    return new RouterAbEd25519YaoClientV1();
  }

  importLocalMaterial(
    input: RouterAbEd25519YaoImportLocalMaterialInputV1,
  ): RouterAbEd25519YaoActiveClientV1 {
    return importVerifiedActiveClient(input);
  }

  importEmailOtpLocalMaterial(
    input: RouterAbEd25519YaoImportEmailOtpLocalMaterialInputV1,
  ): RouterAbEd25519YaoActiveClientV1 {
    return importVerifiedEmailOtpActiveClient(input);
  }

  /**
   * Opens the wallet continuity cache with any factor that opens its custody
   * envelope — the read side cold and warm unlock share.
   */
  openCustodyCache(
    input: RouterAbEd25519YaoOpenCustodyCacheInputV1,
  ): RouterAbEd25519YaoActiveClientV1 {
    return openVerifiedCustodyCacheActiveClient(input);
  }

  async register(args: {
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    factor: RouterAbEd25519YaoCustodySeedV1;
    transport: RouterAbEd25519YaoRegistrationTransportV1;
  }): Promise<RouterAbEd25519YaoRegistrationResultV1> {
    const consumedFactor = consumeOwnedCustodySeed(args.factor);
    if (!consumedFactor.ok) return consumedFactor;
    const factorSecret32 = consumedFactor.value;
    const admissionResponse = await args.transport.send({
      kind: 'admit',
      path: ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
      body: args.request,
    });
    if (!admissionResponse.ok) {
      factorSecret32.fill(0);
      return admissionResponse;
    }
    const admission = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
      admissionResponse.value,
    );
    if (!admission.ok) {
      factorSecret32.fill(0);
      return { ok: false, code: 'invalid_router_response', status: 0, message: admission.message };
    }
    return await this.registerAdmitted({
      request: args.request,
      admissionReceipt: admission.value,
      factor: reownConsumedCustodySeed(factorSecret32),
      transport: args.transport,
    });
  }

  async registerAdmitted(args: {
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    admissionReceipt: RegistrationAdmissionReceiptV1;
    factor: RouterAbEd25519YaoCustodySeedV1;
    transport: RouterAbEd25519YaoRegistrationTransportV1;
  }): Promise<RouterAbEd25519YaoRegistrationResultV1> {
    const consumedFactor = consumeOwnedCustodySeed(args.factor);
    if (!consumedFactor.ok) return consumedFactor;
    const factorSecret32 = consumedFactor.value;
    const admissionStartedAt = performance.now();
    const admission = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
      args.admissionReceipt,
    );
    if (!admission.ok) {
      factorSecret32.fill(0);
      return { ok: false, code: 'invalid_router_response', status: 0, message: admission.message };
    }
    if (!activationAdmissionMatchesScope(args.request.scope, admission.value)) {
      factorSecret32.fill(0);
      return {
        ok: false,
        code: 'invalid_router_response',
        status: 0,
        message: 'Router admission receipt does not match the requested lifecycle scope',
      };
    }

    const admissionMs = performance.now() - admissionStartedAt;
    const entropy = createRouterAbEd25519YaoActivationEntropyV1();
    const sessionCreateStartedAt = performance.now();
    let session: WasmRegistrationSessionV1;
    try {
      session = createRegistrationSession({
        admission: admission.value,
        applicationBinding: args.request.application_binding,
        participantIds: args.request.participant_ids,
        factor: 'wallet_custody_seed',
        secret32: factorSecret32,
        entropy,
      });
    } catch (error) {
      return {
        ok: false,
        code: 'invalid_client_result',
        status: 0,
        message: error instanceof Error ? error.message : String(error),
      };
    } finally {
      factorSecret32.fill(0);
      zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
    }
    const sessionCreateMs = performance.now() - sessionCreateStartedAt;

    try {
      const executeRequest = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(
        JSON.parse(session.execute_request_json()),
      );
      if (!executeRequest.ok) {
        return {
          ok: false,
          code: 'invalid_client_result',
          status: 0,
          message: executeRequest.message,
        };
      }
      const executeResponse = await args.transport.send({
        kind: 'execute',
        path: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
        body: executeRequest.value,
      });
      if (!executeResponse.ok) return executeResponse;
      const result = parseRouterAbEd25519YaoRegistrationActivationResultV1(executeResponse.value);
      if (!result.ok) {
        return { ok: false, code: 'invalid_router_response', status: 0, message: result.message };
      }
      const activated = session.complete(JSON.stringify(result.value));
      try {
        const activeClient = createVerifiedActiveClient({
          activated,
          scope: args.request.scope,
          applicationBinding: args.request.application_binding,
          participantIds: args.request.participant_ids,
          result: result.value,
          activeCapabilityBinding: result.value.binding.session_id,
        });
        return {
          ok: true,
          activeClient,
          ...(executeResponse.serverTiming
            ? { routerServerTiming: executeResponse.serverTiming }
            : {}),
          clientTimings: {
            admissionMs: Math.max(0, admissionMs),
            sessionCreateMs: Math.max(0, sessionCreateMs),
          },
        };
      } catch (error) {
        activated.free();
        throw error;
      }
    } catch (error) {
      return {
        ok: false,
        code: 'invalid_client_result',
        status: 0,
        message: error instanceof Error ? error.message : String(error),
      };
    } finally {
      session.free();
    }
  }

  async recover(args: {
    request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
    factor: RouterAbEd25519YaoCustodySeedV1;
    transport: RouterAbEd25519YaoRecoveryTransportV1;
  }): Promise<RouterAbEd25519YaoRecoveryResultV1> {
    return this.recoverPrepared({
      ...args,
      entropy: createRouterAbEd25519YaoActivationEntropyV1(),
    });
  }

  async recoverPrepared(
    args: RouterAbEd25519YaoPreparedRecoveryInputV1,
  ): Promise<RouterAbEd25519YaoRecoveryResultV1> {
    const factorKind = args.factor.kind;
    const consumedFactor = consumeOwnedCustodySeed(args.factor);
    if (!consumedFactor.ok) {
      zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
      return consumedFactor;
    }
    const factorSecret32 = consumedFactor.value;

    const admissionResponse = await args.transport.send({
      kind: 'recovery_admit',
      path: ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
      body: args.request,
    });
    if (!admissionResponse.ok) {
      factorSecret32.fill(0);
      zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
      return admissionResponse;
    }
    const admission = parseRouterAbEd25519YaoRecoveryActivationAdmissionReceiptV1(
      admissionResponse.value,
    );
    if (!admission.ok) {
      factorSecret32.fill(0);
      zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
      return { ok: false, code: 'invalid_router_response', status: 0, message: admission.message };
    }
    if (!activationAdmissionMatchesScope(args.request.scope, admission.value)) {
      factorSecret32.fill(0);
      zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
      return {
        ok: false,
        code: 'invalid_router_response',
        status: 0,
        message: 'Router recovery admission does not match the requested lifecycle scope',
      };
    }

    return continuePreparedRecovery({
      request: args.request,
      factorKind,
      factorSecret32,
      entropy: args.entropy,
      continuation: { stage: 'admitted', admission: admission.value },
      transport: args.transport,
    });
  }

  async resumePreparedRecovery(
    args: RouterAbEd25519YaoPreparedRecoveryInputV1,
  ): Promise<RouterAbEd25519YaoRecoveryResultV1> {
    const factorKind = args.factor.kind;
    const consumedFactor = consumeOwnedCustodySeed(args.factor);
    if (!consumedFactor.ok) {
      zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
      return consumedFactor;
    }
    const factorSecret32 = consumedFactor.value;
    const status = await readRouterAbEd25519YaoRecoveryStatusV1({
      request: args.request,
      transport: args.transport,
    });
    if (!status.ok) {
      factorSecret32.fill(0);
      zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
      return status;
    }
    const continuation = recoveryContinuationFromStatus(args.request, status.status);
    if (!continuation.ok) {
      factorSecret32.fill(0);
      zeroizeRouterAbEd25519YaoActivationEntropyV1(args.entropy);
      return continuation;
    }
    return continuePreparedRecovery({
      request: args.request,
      factorKind,
      factorSecret32,
      entropy: args.entropy,
      continuation: continuation.value,
      transport: args.transport,
    });
  }

  async exportSeed(
    args: RouterAbEd25519YaoExportSeedInputV1,
  ): Promise<RouterAbEd25519YaoExportResultClientV1> {
    const admissionResponse = await args.transport.send({
      kind: 'export_admit',
      path: ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
      body: buildRouterAbEd25519YaoExportAdmissionBodyV1({
        protocol: args.request,
        authorization: args.authorization,
      }),
    });
    if (!admissionResponse.ok) {
      return admissionResponse;
    }
    const admission = parseRouterAbEd25519YaoExportAdmissionReceiptV1(admissionResponse.value);
    if (!admission.ok) {
      return { ok: false, code: 'invalid_router_response', status: 0, message: admission.message };
    }
    if (!exportAdmissionMatchesRequest(args.request, admission.value)) {
      return {
        ok: false,
        code: 'invalid_router_response',
        status: 0,
        message: 'Router export admission does not match the requested exact capability',
      };
    }

    const entropy = createRouterAbEd25519YaoActivationEntropyV1();
    let session: WasmExportSessionV1;
    try {
      session = createExportSession({
        admission: admission.value,
        applicationBinding: args.request.application_binding,
        participantIds: args.request.participant_ids,
        custodyEnvelope: args.custodyEnvelope,
        entropy,
      });
    } catch (error) {
      return {
        ok: false,
        code: 'invalid_client_result',
        status: 0,
        message: error instanceof Error ? error.message : String(error),
      };
    } finally {
      args.custodyEnvelope.factorSecret.fill(0);
      zeroizeRouterAbEd25519YaoActivationEntropyV1(entropy);
    }

    try {
      const executeRequest = parseRouterAbEd25519YaoExportExecuteRequestV1(
        JSON.parse(session.execute_request_json()),
      );
      if (!executeRequest.ok) {
        return {
          ok: false,
          code: 'invalid_client_result',
          status: 0,
          message: executeRequest.message,
        };
      }
      const executeResponse = await args.transport.send({
        kind: 'export_execute',
        path: ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
        body: {
          protocol: executeRequest.value,
        },
      });
      if (!executeResponse.ok) return executeResponse;
      const result = parseRouterAbEd25519YaoExportResultV1(executeResponse.value);
      if (!result.ok) {
        return { ok: false, code: 'invalid_router_response', status: 0, message: result.message };
      }
      const exported = session.complete(JSON.stringify(result.value));
      try {
        return {
          ok: true,
          artifact: parseExportArtifactJson(exported.take_export_artifact_json()),
        };
      } finally {
        exported.free();
      }
    } catch (error) {
      return {
        ok: false,
        code: 'invalid_client_result',
        status: 0,
        message: error instanceof Error ? error.message : String(error),
      };
    } finally {
      session.free();
    }
  }
}
