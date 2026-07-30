import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import type { SigningAuthPlan } from '@/core/signingEngine/stepUpConfirmation/types';
import {
  buildEvmFamilyEmailOtpStepUpAuthorization,
  buildEvmFamilyPasskeyStepUpAuthorization,
} from '@/core/signingEngine/flows/signEvmFamily/stepUpAuthorization';
import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type {
  EvmFamilyEcdsaOperationStepUpAuthorization,
  EvmFamilyThresholdEcdsaOperation,
} from '@/core/signingEngine/flows/signEvmFamily/thresholdAdmission';
import type {
  EvmFamilyReusableAuthorizationState,
  EvmFamilyThresholdEcdsaStepUpRuntime,
} from '@/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth';
import { resolveHydratedSecp256k1SigningMaterial } from '@/core/signingEngine/flows/signEvmFamily/readySecp256k1Material';
import type { HydratedEcdsaSignerMaterial } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { parseEcdsaRoleLocalWorkerHandle } from '@/core/signingEngine/session/keyMaterialBrands';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
  EcdsaOnlineClientRequestType,
  EcdsaOnlineClientResponseType,
  EcdsaPresignClientRequestType,
  EcdsaPresignClientResponseType,
  type SignerWorkerKind,
  type SignerWorkerOperationRequest,
  type SignerWorkerOperationResult,
  type SignerWorkerOperationType,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  type RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import { canonicalEvmFamilyEcdsaSigningCapabilityFixture } from './ecdsaCapabilityManifest.fixtures';
import {
  buildEmailOtpEcdsaSealedRuntimeRecordFixture,
  buildPasskeyEcdsaSealedRuntimeRecordFixture,
} from './sealedSigningSession.fixtures';

export type EcdsaFixtureFactor = 'passkey' | 'email_otp';
type EcdsaSigningCapabilityFixture = Awaited<
  ReturnType<typeof canonicalEvmFamilyEcdsaSigningCapabilityFixture>
>;

type RecordedWorkerOperation = {
  kind: SignerWorkerKind;
  request: { type: number | string; payload?: unknown };
};

const PRESIGNATURE_BIG_R_33 = Uint8Array.from(
  Buffer.from('03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8', 'hex'),
);

function requestPayload(args: RecordedWorkerOperation): Record<string, unknown> {
  const payload = args.request.payload;
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error(`[fixture] worker operation ${String(args.request.type)} requires a payload`);
  }
  return payload as Record<string, unknown>;
}

export class RecordingEcdsaRehydrationWorker implements WorkerOperationContext {
  readonly requests: RecordedWorkerOperation[] = [];

  constructor(private readonly manifest: ActiveEcdsaCapabilityManifest) {}

  async requestWorkerOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>>;
  async requestWorkerOperation(args: RecordedWorkerOperation): Promise<unknown> {
    this.requests.push(args);
    if (
      args.kind === 'ecdsaDerivationClient' &&
      args.request.type ===
        EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial
    ) {
      const durable = this.manifest.durableMaterial;
      return {
        type: EcdsaDerivationClientCustomResponseType.RehydrateEcdsaRoleLocalSigningMaterialSuccess,
        payload: {
          kind: 'ecdsa_role_local_signing_material_opened_v1',
          ok: true,
          liveHandle: parseEcdsaRoleLocalWorkerHandle({
            kind: 'ecdsa_role_local_worker_handle_v1',
            materialHandle: `${String(durable.durableMaterialRef)}:live`,
            bindingDigest: String(durable.bindingDigest),
            durableMaterialRef: durable.durableMaterialRef,
          }),
          materialRef: {
            kind: 'ecdsa_role_local_persisted_material_ref_v1',
            durableMaterialRef: durable.durableMaterialRef,
            bindingDigest: durable.bindingDigest,
            materialActivation: durable.materialActivation,
          },
        },
      };
    }
    if (
      args.kind === 'ecdsaPresignClient' &&
      args.request.type === EcdsaPresignClientRequestType.ListAvailable
    ) {
      return {
        type: EcdsaPresignClientResponseType.ListAvailableSuccess,
        payload: [
          {
            presignatureId: 'operating-path-presignature',
            materialHandle: `${String(this.manifest.durableMaterial.durableMaterialRef)}:presignature`,
            bigR33: PRESIGNATURE_BIG_R_33.slice().buffer,
            createdAtMs: Date.now() - 1_000,
            expiresAtMs: Date.now() + 10 * 60_000,
          },
        ],
      };
    }
    if (
      args.kind === 'ecdsaPresignClient' &&
      (args.request.type === EcdsaPresignClientRequestType.Reserve ||
        args.request.type === EcdsaPresignClientRequestType.Commit)
    ) {
      return {
        type:
          args.request.type === EcdsaPresignClientRequestType.Reserve
            ? EcdsaPresignClientResponseType.ReserveSuccess
            : EcdsaPresignClientResponseType.CommitSuccess,
        payload: {
          kind: 'ecdsa_client_presignature_lifecycle_advanced_v1',
          materialHandle: String(requestPayload(args).materialHandle),
        },
      };
    }
    if (
      args.kind === 'ecdsaOnlineClient' &&
      args.request.type === EcdsaOnlineClientRequestType.ComputeSignatureShare
    ) {
      return {
        type: EcdsaOnlineClientResponseType.ComputeSignatureShareSuccess,
        payload: new Uint8Array(32).fill(17).buffer,
      };
    }
    if (args.kind === 'evmCrypto' && args.request.type === 'validateSecp256k1PublicKey33') {
      return requestPayload(args).publicKey33;
    }
    if (
      args.kind === 'evmCrypto' &&
      args.request.type === 'verifySecp256k1RecoverableSignatureAgainstPublicKey33'
    ) {
      return requestPayload(args).publicKey33;
    }
    throw new Error(
      `[fixture] unexpected ${args.kind} worker operation ${String(args.request.type)}`,
    );
  }
}

export async function canonicalEcdsaSealedRuntimeFixture(factor: EcdsaFixtureFactor) {
  const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture(factor);
  const { manifest } = fixture;
  const record =
    factor === 'passkey'
      ? buildPasskeyEcdsaSealedRuntimeRecordFixture({ manifest })
      : buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId: toWalletId(String(manifest.signer.walletId)),
    chainTarget: record.ecdsaRestore.chainTarget,
    sealedRecords: [record],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`[fixture] ${factor} sealed runtime did not resolve: ${resolution.reason}`);
  }
  return {
    fixture,
    runtime: resolution.runtime,
    worker: new RecordingEcdsaRehydrationWorker(manifest),
  };
}

export async function hydratedEcdsaSigningMaterialFixture(factor: EcdsaFixtureFactor): Promise<{
  fixture: EcdsaSigningCapabilityFixture;
  material: HydratedEcdsaSignerMaterial;
  runtime: Awaited<ReturnType<typeof canonicalEcdsaSealedRuntimeFixture>>['runtime'];
  worker: RecordingEcdsaRehydrationWorker;
}> {
  const { fixture, runtime, worker } = await canonicalEcdsaSealedRuntimeFixture(factor);
  const { capability, manifest } = fixture;
  const materialResolution = await resolveHydratedSecp256k1SigningMaterial({
    capability,
    runtime,
    chainTarget: runtime.chainTarget,
    materialActivation: manifest.activation.materialActivation,
    workerCtx: worker,
  });
  if (materialResolution.kind !== 'ready') {
    throw new Error(`[fixture] ${factor} material did not hydrate: ${materialResolution.reason}`);
  }
  return { fixture, material: materialResolution.material, runtime, worker };
}

export function ecdsaOperationDigestSetFixture(): OperationDigestSet {
  return {
    laneDigest: parseDigestB64u(Buffer.from(new Uint8Array(32).fill(11)).toString('base64url')),
    intentDigest: parseDigestB64u(Buffer.from(new Uint8Array(32).fill(12)).toString('base64url')),
    displayDigest: parseDigestB64u(Buffer.from(new Uint8Array(32).fill(13)).toString('base64url')),
  };
}

export type RecordedEcdsaNormalSigningRequest =
  | {
      readonly kind: 'prepare';
      readonly request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
    }
  | {
      readonly kind: 'finalize';
      readonly request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire;
    };

export function installEcdsaNormalSigningEndpointFixture(): {
  readonly requests: RecordedEcdsaNormalSigningRequest[];
  readonly signature65: Uint8Array;
  readonly restore: () => void;
} {
  const originalFetch = globalThis.fetch;
  const requests: RecordedEcdsaNormalSigningRequest[] = [];
  const signature65 = new Uint8Array(65).fill(16);
  signature65[64] = 0;
  globalThis.fetch = async (input, init) => {
    const url = String(input);
    const rawRequest = JSON.parse(String(init?.body || '{}')) as unknown;
    if (url.endsWith('/router-ab/ecdsa-derivation/sign/prepare')) {
      const request = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(rawRequest);
      requests.push({ kind: 'prepare', request });
      return new Response(
        JSON.stringify({
          scope: request.scope,
          request_id: request.request_id,
          request_digest: await routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(request),
          signing_digest: { bytes: Array.from(base64UrlDecode(request.signing_digest_b64u)) },
          server_presignature_id: request.client_presignature_id,
          server_big_r33_b64u: base64UrlEncode(PRESIGNATURE_BIG_R_33),
          signing_worker_rerandomization_contribution32_b64u: base64UrlEncode(
            new Uint8Array(32).fill(14),
          ),
          signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
          prepared_at_ms: Date.now(),
          expires_at_ms: request.expires_at_ms,
          // Required by the prepare wire contract since operation claims became
          // canonical: the server names the claim row the prepared signature
          // will consume, and reports the budget projection it reserved from.
          budget_reservation_id: 'budget-reservation-fixture',
          budget_operation_id: 'budget-operation-fixture',
          budget_status: {
            remaining_uses: 3,
            committed_remaining_uses: 3,
            reserved_uses: 1,
            available_uses: 2,
            projection_version: 1,
            expires_at_ms: request.expires_at_ms,
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    if (url.endsWith('/router-ab/ecdsa-derivation/sign')) {
      const request = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(rawRequest);
      requests.push({ kind: 'finalize', request });
      return new Response(
        JSON.stringify({
          scope: request.scope,
          request_id: request.request_id,
          request_digest:
            await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(request),
          signing_digest: { bytes: Array.from(base64UrlDecode(request.signing_digest_b64u)) },
          signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
          signature65_b64u: base64UrlEncode(signature65),
          budget_status: {
            remaining_uses: 2,
            committed_remaining_uses: 2,
            reserved_uses: 0,
            available_uses: 2,
            projection_version: 2,
            expires_at_ms: request.expires_at_ms,
          },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }
    throw new Error(`[fixture] unexpected ECDSA signing endpoint ${url}`);
  };
  return {
    requests,
    signature65,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

export function evmFamilyThresholdEcdsaOperationFixture(args?: {
  operationId?: string;
  authPlan?: SigningAuthPlan;
}): EvmFamilyThresholdEcdsaOperation {
  return {
    intent: {
      operationId: SigningSessionIds.signingOperation(
        args?.operationId ?? 'ecdsa-step-up-operation',
      ),
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: 1,
      walletId: toWalletId('ecdsa-step-up-wallet'),
      curve: 'ecdsa',
      chain: 'evm',
      chainTarget: {
        kind: 'evm',
        namespace: 'eip155',
        chainId: 1,
        networkSlug: 'ethereum',
      },
    },
    authPlan: args?.authPlan ?? { kind: 'passkeyReauth', method: 'passkey' },
  };
}

async function unusedOperationStepUpPrepare(): Promise<never> {
  throw new Error('[fixture] operation step-up prepare was not expected');
}

async function unusedOperationStepUpAuthorize(): Promise<never> {
  throw new Error('[fixture] operation step-up authorize was not expected');
}

function operationStepUpRuntime() {
  return {
    prepare: unusedOperationStepUpPrepare,
    authorize: unusedOperationStepUpAuthorize,
  };
}

export function evmFamilyThresholdEcdsaStepUpRuntimeFixture(args: {
  reusableAuthorization: EvmFamilyReusableAuthorizationState;
  emailOtpChallenge?: { challengeId: string; emailHint?: string };
}): EvmFamilyThresholdEcdsaStepUpRuntime {
  if (!args.emailOtpChallenge) {
    return {
      reusableAuthorization: args.reusableAuthorization,
      operationStepUp: operationStepUpRuntime(),
    };
  }
  const challenge = args.emailOtpChallenge;
  async function prepareEmailOtpChallenge() {
    return challenge;
  }
  return {
    reusableAuthorization: args.reusableAuthorization,
    operationStepUp: operationStepUpRuntime(),
    emailOtpSigning: { prepare: prepareEmailOtpChallenge },
  };
}

export function ecdsaOperationStepUpAuthorizationFixture(
  factor: EcdsaFixtureFactor,
): EvmFamilyEcdsaOperationStepUpAuthorization {
  if (factor === 'email_otp') {
    const signingAuthPlan = { kind: 'emailOtpReauth' as const, method: 'email_otp' as const };
    return buildEvmFamilyEmailOtpStepUpAuthorization({
      signingAuthPlan,
      prompt: { challengeId: 'ecdsa-step-up-otp-challenge' },
      confirmation: {
        emailOtpChallengeId: 'ecdsa-step-up-otp-challenge',
        otpCode: '123456',
      },
    });
  }
  return buildEvmFamilyPasskeyStepUpAuthorization({
    signingAuthPlan: { kind: 'passkeyReauth', method: 'passkey' },
    confirmation: {
      credential: normalizeAuthenticationCredential({
        id: 'credential-passkey-fixture',
        rawId: 'raw-id',
        type: 'public-key',
        authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: 'client-data',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
        },
      }),
    },
  });
}
