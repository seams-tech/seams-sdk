import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
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
  type SignerWorkerKind,
  type SignerWorkerOperationRequest,
  type SignerWorkerOperationResult,
  type SignerWorkerOperationType,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
} from './ecdsaCapabilityManifest.fixtures';
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
  request: { type: number };
};

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
    if (args.kind !== 'ecdsaDerivationClient') {
      throw new Error(`[fixture] unexpected worker kind ${args.kind}`);
    }
    if (args.request.type !== EcdsaDerivationClientCustomRequestType.RehydrateEcdsaRoleLocalSigningMaterial) {
      throw new Error(`[fixture] unexpected worker operation ${args.request.type}`);
    }
    this.requests.push(args);
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
    requestLabel: runtime.chainTarget.kind,
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

export function evmFamilyThresholdEcdsaOperationFixture(args?: {
  operationId?: string;
  authPlan?: SigningAuthPlan;
}): EvmFamilyThresholdEcdsaOperation {
  return {
    intent: {
      operationId: SigningSessionIds.signingOperation(args?.operationId ?? 'ecdsa-step-up-operation'),
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
