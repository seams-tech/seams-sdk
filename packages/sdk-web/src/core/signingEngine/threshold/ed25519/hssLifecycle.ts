import type { AccountId } from '@/core/types/accountIds';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import { getPrfResultsFromCredential } from '../../webauthnAuth/credentials/credentialExtensions';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  ROUTER_AB_ED25519_HSS_FINALIZE_PATH,
  ROUTER_AB_ED25519_HSS_PREPARE_PATH,
  ROUTER_AB_ED25519_HSS_RESPOND_PATH,
} from '@shared/utils/signingSessionSeal';
import {
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm,
  buildThresholdEd25519SeedExportArtifactWasm,
  openThresholdEd25519HssSeedOutputWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssClientOutputMaskHandleWasm,
  type ThresholdEd25519HssCanonicalContext,
  type ThresholdEd25519HssClientRequestEnvelope,
  type ThresholdEd25519HssClientInputs,
  type ThresholdEd25519HssFinalizedReportEnvelope,
  type ThresholdEd25519HssOpenedSeedOutput,
  type ThresholdEd25519HssPreparedSessionEnvelope,
  type ThresholdEd25519HssServerInputDeliveryEnvelope,
  type ThresholdEd25519SeedExportArtifact,
  type ThresholdEd25519HssStagedEvaluatorArtifactEnvelope,
} from '../crypto/hssClientSignerWasm';
import { storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm } from '../../chains/near/nearSignerWasm';
import type {
  ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult,
  ThresholdEd25519WorkerMaterialStoredResult,
} from '@/core/types/signer-worker';
import { THRESHOLD_ED25519_WRAP_KEY_SALT_B64U } from '../crypto/ed25519WrapKeySalt';
import {
  resolveThresholdEd25519HssClientOutputMaskHandle,
  validateThresholdEd25519HssOutputProjectionPolicy,
  type ThresholdEd25519HssClientOutputMaskContext,
  type ThresholdEd25519HssClientOutputMaskOperation,
  type ThresholdEd25519HssOutputProjectionPolicy,
} from './clientOutputMask';
import {
  computeSdkEd25519HssApplicationBindingDigestB64u,
  type SdkEd25519HssBindingFacts,
} from '@shared/threshold/ed25519HssBinding';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';

export type ThresholdEd25519LifecycleDeps = {
  signingKeyOps: Pick<
    NearSigningKeyOps,
    'deriveThresholdEd25519ClientVerifyingShare' | 'deriveThresholdEd25519HssClientInputs'
  >;
  createSessionId: (prefix: string) => string;
  getSignerWorkerContext: () => WorkerOperationContext;
};

export type DeriveThresholdEd25519ClientVerifyingShareResult =
  | {
      ok: true;
      nearAccountId: string;
      clientVerifyingShareB64u: string;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      nearAccountId: string;
      code: 'derive_client_verifying_share_failed';
      message: string;
      clientVerifyingShareB64u?: never;
    };

type ThresholdEd25519HssClientInputsSuccess = {
  ok: true;
  hssContext: ThresholdEd25519HssCanonicalContext;
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
  code?: never;
  message?: never;
};

type ThresholdEd25519HssClientInputsFailure<
  Code extends 'derive_client_inputs_failed' | 'prepare_client_ceremony_failed',
> = {
  ok: false;
  code: Code;
  message: string;
  hssContext?: never;
  contextBindingB64u?: never;
  yClientB64u?: never;
  tauClientB64u?: never;
};

export type DeriveThresholdEd25519HssClientInputsResult =
  | ThresholdEd25519HssClientInputsSuccess
  | ThresholdEd25519HssClientInputsFailure<'derive_client_inputs_failed'>;

export type PrepareThresholdEd25519HssClientCeremonyResult =
  | ThresholdEd25519HssClientInputsSuccess
  | ThresholdEd25519HssClientInputsFailure<
      'derive_client_inputs_failed' | 'prepare_client_ceremony_failed'
    >;

export type CompleteThresholdEd25519HssClientCeremonyResult =
  | {
      ok: true;
      contextBindingB64u: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'complete_client_ceremony_failed';
      message: string;
      preparedSession?: never;
      finalizedReport?: never;
    };

export type CompleteThresholdEd25519HssMaterialHandleCeremonyResult =
  | {
      ok: true;
      contextBindingB64u: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
      signingMaterial: ThresholdEd25519WorkerMaterialStoredResult;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'complete_client_ceremony_failed';
      message: string;
      preparedSession?: never;
      finalizedReport?: never;
      signingMaterial?: never;
    };

export type StoreThresholdEd25519WorkerMaterialFromFinalizedHssReportResult =
  | {
      ok: true;
      contextBindingB64u: string;
      signingMaterial: ThresholdEd25519WorkerMaterialStoredResult;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'store_worker_material_failed';
      message: string;
      signingMaterial?: never;
    };

export type PrepareThresholdEd25519HssServerCeremonyWithSessionResult =
  | {
      ok: true;
      contextBindingB64u: string;
      ceremonyHandle: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      clientOtOfferMessageB64u: string;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'server_prepare_failed';
      message: string;
      ceremonyHandle?: never;
      preparedSession?: never;
      clientOtOfferMessageB64u?: never;
    };

export type ThresholdEd25519HssSessionOperation =
  | 'tx_signing'
  | 'link_device'
  | 'email_recovery'
  | 'registration_material_restore'
  | 'warm_session_reconstruction'
  | 'explicit_key_export';

function assertNeverThresholdEd25519HssSessionOperation(value: never): never {
  throw new Error(`Unsupported threshold Ed25519 HSS session operation: ${String(value)}`);
}

function clientOutputMaskOperationForSessionOperation(
  operation: ThresholdEd25519HssSessionOperation,
): ThresholdEd25519HssClientOutputMaskOperation {
  switch (operation) {
    case 'tx_signing':
    case 'link_device':
    case 'email_recovery':
    case 'warm_session_reconstruction':
    case 'explicit_key_export':
      return operation;
    case 'registration_material_restore':
      return 'registration';
    default:
      return assertNeverThresholdEd25519HssSessionOperation(operation);
  }
}

export type RespondThresholdEd25519HssServerCeremonyWithSessionResult =
  | {
      ok: true;
      contextBindingB64u: string;
      serverInputDelivery: ThresholdEd25519HssServerInputDeliveryEnvelope;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'server_respond_failed';
      message: string;
      serverInputDelivery?: never;
    };

export type FinalizeThresholdEd25519HssServerCeremonyWithSessionResult =
  | {
      ok: true;
      contextBindingB64u: string;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'server_finalize_failed';
      message: string;
      finalizedReport?: never;
    };

export type OpenThresholdEd25519HssSeedOutputResult =
  | {
      ok: true;
      contextBindingB64u: string;
      seedOutput: ThresholdEd25519HssOpenedSeedOutput;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'open_seed_output_failed';
      message: string;
      seedOutput?: never;
    };

export type BuildThresholdEd25519SeedExportArtifactResult =
  | {
      ok: true;
      contextBindingB64u: string;
      seedOutput: ThresholdEd25519HssOpenedSeedOutput;
      artifact: ThresholdEd25519SeedExportArtifact;
      code?: never;
      message?: never;
    }
  | {
      ok: false;
      contextBindingB64u: string;
      code: 'open_seed_output_failed' | 'build_seed_export_artifact_failed';
      message: string;
      seedOutput?: never;
      artifact?: never;
    };

function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, '');
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length;
}

function jsonBytes(value: unknown): number {
  return utf8Bytes(JSON.stringify(value));
}

type ThresholdEd25519HssBindingFactsInput = {
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signingRootId: string;
  signingRootVersion: string;
};

function normalizeThresholdEd25519HssBindingFacts(
  input: ThresholdEd25519HssBindingFactsInput,
): SdkEd25519HssBindingFacts {
  return {
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    signingRootId: parseSdkEcdsaHssSigningRootId(input.signingRootId),
    signingRootVersion: parseSdkEcdsaHssSigningRootVersion(input.signingRootVersion),
  };
}

async function buildThresholdEd25519HssCanonicalContext(args: {
  hssBindingFacts: ThresholdEd25519HssBindingFactsInput;
  participantIds: number[];
}): Promise<ThresholdEd25519HssCanonicalContext> {
  const participantIds = Array.isArray(args.participantIds)
    ? args.participantIds.map((value) => Number(value))
    : [];
  if (!participantIds.length || participantIds.some((value) => !Number.isSafeInteger(value))) {
    throw new Error('participantIds are required for threshold Ed25519 HSS context');
  }
  return {
    applicationBindingDigestB64u: await computeSdkEd25519HssApplicationBindingDigestB64u(
      normalizeThresholdEd25519HssBindingFacts(args.hssBindingFacts),
    ),
    participantIds,
  };
}

function assertMatchingThresholdEd25519HssDerivedContext(args: {
  expected: ThresholdEd25519HssCanonicalContext;
  actual: {
    applicationBindingDigestB64u: string;
    participantIds: number[];
  };
}): void {
  const actualDigest = String(args.actual.applicationBindingDigestB64u || '').trim();
  if (actualDigest !== args.expected.applicationBindingDigestB64u) {
    throw new Error('Threshold Ed25519 HSS application binding digest mismatch');
  }
  const actualParticipants = Array.isArray(args.actual.participantIds)
    ? args.actual.participantIds.map((value) => Number(value))
    : [];
  if (
    actualParticipants.length !== args.expected.participantIds.length ||
    actualParticipants.some((value, index) => value !== args.expected.participantIds[index])
  ) {
    throw new Error('Threshold Ed25519 HSS participant set mismatch');
  }
}

function summarizePrepareRequestSize(args: {
  relayerKeyId: string;
  context: ThresholdEd25519HssCanonicalContext;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
}): Record<string, number> {
  return {
    relayerKeyIdBytes: utf8Bytes(args.relayerKeyId),
    contextBytes: jsonBytes(args.context),
    preparedSessionBytes: jsonBytes(args.preparedSession),
    preparedSessionContextBindingBytes: utf8Bytes(args.preparedSession.contextBindingB64u),
    preparedSessionEvaluatorDriverStateBytes: utf8Bytes(
      args.preparedSession.evaluatorDriverStateB64u,
    ),
  };
}

function summarizeRespondRequestSize(args: {
  ceremonyHandle: string;
  clientRequest: Pick<ThresholdEd25519HssClientRequestEnvelope, 'clientRequestMessageB64u'>;
}): Record<string, number> {
  return {
    ceremonyHandleBytes: utf8Bytes(args.ceremonyHandle),
    clientRequestBytes: jsonBytes(args.clientRequest),
    clientRequestMessageBytes: utf8Bytes(args.clientRequest.clientRequestMessageB64u),
  };
}

function requirePrfFirstB64uFromCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): string {
  const value = getPrfResultsFromCredential(credential).first;
  if (!value) {
    throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
  }
  return value;
}

async function prepareClientOwnedEvaluatorMaskHandle(args: {
  outputProjection: ThresholdEd25519HssOutputProjectionPolicy;
  context: ThresholdEd25519HssCanonicalContext;
  contextBindingB64u: string;
  operation: ThresholdEd25519HssClientOutputMaskOperation;
  relayerKeyId: string;
  workerCtx: WorkerOperationContext;
}): Promise<string> {
  validateThresholdEd25519HssOutputProjectionPolicy(args.outputProjection);
  const result = await prepareThresholdEd25519HssClientOutputMaskHandleWasm({
    clientRecoverableSecretB64u: args.outputProjection.clientRecoverableSecretB64u,
    context: {
      applicationBindingDigestB64u: args.context.applicationBindingDigestB64u,
      participantIds: args.context.participantIds,
      contextBindingB64u: args.contextBindingB64u,
      operation: args.operation,
      relayerKeyId: args.relayerKeyId,
    },
    expiresAtMs: Date.now() + 60_000,
    workerCtx: args.workerCtx,
  });
  if (result.contextBindingB64u !== args.contextBindingB64u) {
    throw new Error('Ed25519 HSS client output mask handle context binding mismatch');
  }
  return result.clientOutputMaskHandle;
}

export async function deriveThresholdEd25519ClientVerifyingShareFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId;
  },
): Promise<DeriveThresholdEd25519ClientVerifyingShareResult> {
  const nearAccountId = args.nearAccountId;
  try {
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-client-share');
    const derived = await deps.signingKeyOps.deriveThresholdEd25519ClientVerifyingShare({
      sessionId,
      nearAccountId,
      prfFirstB64u,
      wrapKeySalt: THRESHOLD_ED25519_WRAP_KEY_SALT_B64U,
    });
    if (!derived.success) {
      return {
        ok: false,
        nearAccountId,
        code: 'derive_client_verifying_share_failed',
        message: String(derived.error || 'Failed to derive threshold Ed25519 client share'),
      };
    }
    return {
      ok: true,
      nearAccountId: derived.nearAccountId,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      nearAccountId,
      code: 'derive_client_verifying_share_failed',
      message,
    };
  }
}

export async function deriveThresholdEd25519ClientVerifyingShareFromPrfFirst(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    prfFirstB64u: string;
    nearAccountId: AccountId;
  },
): Promise<DeriveThresholdEd25519ClientVerifyingShareResult> {
  const nearAccountId = args.nearAccountId;
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  try {
    if (!prfFirstB64u) {
      throw new Error('prfFirstB64u is required for threshold Ed25519 verifier derivation');
    }
    const sessionId = deps.createSessionId('threshold-client-share');
    const derived = await deps.signingKeyOps.deriveThresholdEd25519ClientVerifyingShare({
      sessionId,
      nearAccountId,
      prfFirstB64u,
      wrapKeySalt: THRESHOLD_ED25519_WRAP_KEY_SALT_B64U,
    });
    if (!derived.success) {
      return {
        ok: false,
        nearAccountId,
        code: 'derive_client_verifying_share_failed',
        message: String(derived.error || 'Failed to derive threshold Ed25519 client share'),
      };
    }
    return {
      ok: true,
      nearAccountId: derived.nearAccountId,
      clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      nearAccountId,
      code: 'derive_client_verifying_share_failed',
      message,
    };
  }
}

export async function deriveThresholdEd25519HssClientInputsFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    hssBindingFacts: ThresholdEd25519HssBindingFactsInput;
    participantIds: number[];
  },
): Promise<DeriveThresholdEd25519HssClientInputsResult> {
  try {
    const hssContext = await buildThresholdEd25519HssCanonicalContext({
      hssBindingFacts: args.hssBindingFacts,
      participantIds: args.participantIds,
    });
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-ed25519-hss-client-inputs');
    const derived = await deps.signingKeyOps.deriveThresholdEd25519HssClientInputs({
      sessionId,
      applicationBindingDigestB64u: hssContext.applicationBindingDigestB64u,
      participantIds: hssContext.participantIds,
      prfFirstB64u,
    });
    if (!derived.success) {
      return {
        ok: false,
        code: 'derive_client_inputs_failed',
        message: String(derived.error || 'Failed to derive threshold Ed25519 HSS client inputs'),
      };
    }
    assertMatchingThresholdEd25519HssDerivedContext({
      expected: hssContext,
      actual: derived,
    });
    return {
      ok: true,
      hssContext,
      contextBindingB64u: derived.contextBindingB64u,
      yClientB64u: derived.yClientB64u,
      tauClientB64u: derived.tauClientB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      code: 'derive_client_inputs_failed',
      message,
    };
  }
}

export async function deriveThresholdEd25519HssClientInputsFromPrfFirst(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    prfFirstB64u: string;
    hssBindingFacts: ThresholdEd25519HssBindingFactsInput;
    participantIds: number[];
  },
): Promise<DeriveThresholdEd25519HssClientInputsResult> {
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();

  try {
    if (!prfFirstB64u) {
      throw new Error('prfFirstB64u is required for threshold Ed25519 HSS client inputs');
    }
    const hssContext = await buildThresholdEd25519HssCanonicalContext({
      hssBindingFacts: args.hssBindingFacts,
      participantIds: args.participantIds,
    });
    const sessionId = deps.createSessionId('threshold-ed25519-hss-client-inputs');
    const derived = await deps.signingKeyOps.deriveThresholdEd25519HssClientInputs({
      sessionId,
      applicationBindingDigestB64u: hssContext.applicationBindingDigestB64u,
      participantIds: hssContext.participantIds,
      prfFirstB64u,
    });
    if (!derived.success) {
      return {
        ok: false,
        code: 'derive_client_inputs_failed',
        message: String(derived.error || 'Failed to derive threshold Ed25519 HSS client inputs'),
      };
    }
    assertMatchingThresholdEd25519HssDerivedContext({
      expected: hssContext,
      actual: derived,
    });
    return {
      ok: true,
      hssContext,
      contextBindingB64u: derived.contextBindingB64u,
      yClientB64u: derived.yClientB64u,
      tauClientB64u: derived.tauClientB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      code: 'derive_client_inputs_failed',
      message,
    };
  }
}

export async function deriveThresholdEd25519HssClientInputsFromCredentialAndContext(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    hssContext: ThresholdEd25519HssCanonicalContext;
  },
): Promise<DeriveThresholdEd25519HssClientInputsResult> {
  try {
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-ed25519-hss-client-inputs');
    const derived = await deps.signingKeyOps.deriveThresholdEd25519HssClientInputs({
      sessionId,
      applicationBindingDigestB64u: args.hssContext.applicationBindingDigestB64u,
      participantIds: args.hssContext.participantIds,
      prfFirstB64u,
    });
    if (!derived.success) {
      return {
        ok: false,
        code: 'derive_client_inputs_failed',
        message: String(derived.error || 'Failed to derive threshold Ed25519 HSS client inputs'),
      };
    }
    assertMatchingThresholdEd25519HssDerivedContext({
      expected: args.hssContext,
      actual: derived,
    });
    return {
      ok: true,
      hssContext: args.hssContext,
      contextBindingB64u: derived.contextBindingB64u,
      yClientB64u: derived.yClientB64u,
      tauClientB64u: derived.tauClientB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      code: 'derive_client_inputs_failed',
      message,
    };
  }
}

export async function prepareThresholdEd25519HssClientCeremonyFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    hssBindingFacts: ThresholdEd25519HssBindingFactsInput;
    participantIds: number[];
    onProgress?: (message: string) => void;
  },
): Promise<PrepareThresholdEd25519HssClientCeremonyResult> {
  args.onProgress?.('Deriving threshold Ed25519 client inputs from passkey...');
  const derived = await deriveThresholdEd25519HssClientInputsFromCredential(deps, args);
  if (!derived.ok) {
    return {
      ok: false,
      code: derived.code,
      message: derived.message,
    };
  }

  try {
    return {
      ok: true,
      hssContext: derived.hssContext,
      contextBindingB64u: derived.contextBindingB64u,
      yClientB64u: derived.yClientB64u,
      tauClientB64u: derived.tauClientB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      code: 'prepare_client_ceremony_failed',
      message,
    };
  }
}

export async function prepareThresholdEd25519HssClientCeremonyFromCanonicalContext(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    hssContext: ThresholdEd25519HssCanonicalContext;
    onProgress?: (message: string) => void;
  },
): Promise<PrepareThresholdEd25519HssClientCeremonyResult> {
  args.onProgress?.('Deriving threshold Ed25519 client inputs from canonical HSS context...');
  const derived = await deriveThresholdEd25519HssClientInputsFromCredentialAndContext(deps, args);
  if (!derived.ok) {
    return {
      ok: false,
      code: derived.code,
      message: derived.message,
    };
  }
  return {
    ok: true,
    hssContext: derived.hssContext,
    contextBindingB64u: derived.contextBindingB64u,
    yClientB64u: derived.yClientB64u,
    tauClientB64u: derived.tauClientB64u,
  };
}

export async function prepareThresholdEd25519HssClientCeremonyFromPrfFirst(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    prfFirstB64u: string;
    hssBindingFacts: ThresholdEd25519HssBindingFactsInput;
    participantIds: number[];
    onProgress?: (message: string) => void;
  },
): Promise<PrepareThresholdEd25519HssClientCeremonyResult> {
  args.onProgress?.('Deriving threshold Ed25519 client inputs from Email OTP material...');
  const derived = await deriveThresholdEd25519HssClientInputsFromPrfFirst(deps, args);
  if (!derived.ok) {
    return {
      ok: false,
      code: derived.code,
      message: derived.message,
    };
  }
  return {
    ok: true,
    hssContext: derived.hssContext,
    contextBindingB64u: derived.contextBindingB64u,
    yClientB64u: derived.yClientB64u,
    tauClientB64u: derived.tauClientB64u,
  };
}

export async function prepareThresholdEd25519HssServerCeremonyWithSession(args: {
  relayerUrl: string;
  walletSessionJwt: string;
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  context: ThresholdEd25519HssCanonicalContext;
}): Promise<PrepareThresholdEd25519HssServerCeremonyWithSessionResult> {
  const contextBindingB64u = '';
  try {
    const startedAt = Date.now();
    const relayerUrl = stripTrailingSlashes(String(args.relayerUrl || '').trim());
    const walletSessionJwt = String(args.walletSessionJwt || '').trim();
    const relayerKeyId = String(args.relayerKeyId || '').trim();
    const operation = String(args.operation || '').trim();
    if (!relayerUrl) throw new Error('Missing relayerUrl for Ed25519 HSS server prepare');
    if (!walletSessionJwt) {
      throw new Error('Missing Wallet Session JWT for Ed25519 HSS server prepare');
    }
    if (!relayerKeyId) throw new Error('Missing relayerKeyId for Ed25519 HSS server prepare');
    if (!operation) throw new Error('Missing operation for Ed25519 HSS server prepare');
    if (typeof fetch !== 'function') {
      throw new Error('fetch is not available for Ed25519 HSS server prepare');
    }

    const requestPayload = {
      relayerKeyId,
      operation,
      context: args.context,
    };
    const serializeStartedAt = Date.now();
    const requestBody = JSON.stringify(requestPayload);
    const serializeMs = Date.now() - serializeStartedAt;
    const requestBytes = utf8Bytes(requestBody);
    const requestSizeBreakdown = summarizePrepareRequestSize({
      relayerKeyId,
      context: requestPayload.context,
      preparedSession: {
        contextBindingB64u: '',
        evaluatorDriverStateB64u: '',
      },
    });

    const fetchStartedAt = Date.now();
    const response = await fetch(`${relayerUrl}${ROUTER_AB_ED25519_HSS_PREPARE_PATH}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${walletSessionJwt}`,
      },
      credentials: 'omit',
      body: requestBody,
    });
    const fetchMs = Date.now() - fetchStartedAt;

    const parseStartedAt = Date.now();
    const data = (await response.json().catch(() => ({}))) as Partial<{
      ok: boolean;
      ceremonyHandle: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      clientOtOfferMessageB64u: string;
      code: string;
      message: string;
    }>;
    const parseMs = Date.now() - parseStartedAt;
    const ceremonyHandle = String(data.ceremonyHandle || '').trim();
    const preparedSession =
      data.preparedSession &&
      typeof data.preparedSession === 'object' &&
      !Array.isArray(data.preparedSession)
        ? (data.preparedSession as ThresholdEd25519HssPreparedSessionEnvelope)
        : undefined;
    const clientOtOfferMessageB64u = String(data.clientOtOfferMessageB64u || '').trim();
    if (
      !response.ok ||
      data.ok !== true ||
      !ceremonyHandle ||
      !clientOtOfferMessageB64u ||
      !preparedSession
    ) {
      throw new Error(data.message || data.code || `HTTP ${response.status}`);
    }
    const responsePayload = {
      ceremonyHandle,
      preparedSession,
      clientOtOfferMessageB64u,
    };
    const responseBytes = jsonBytes(responsePayload);
    const responseSizeBreakdown = {
      ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
      preparedSessionBytes: jsonBytes(preparedSession),
      clientOtOfferMessageBytes: utf8Bytes(clientOtOfferMessageB64u),
    };
    console.info('[threshold-ed25519][client] hss prepare timings', {
      relayerKeyId,
      serializeMs,
      fetchMs,
      parseMs,
      requestBytes,
      requestSizeBreakdown,
      responseBytes,
      responseSizeBreakdown,
      totalMs: Date.now() - startedAt,
    });
    return {
      ok: true,
      contextBindingB64u: String(preparedSession.contextBindingB64u || '').trim(),
      ceremonyHandle,
      preparedSession,
      clientOtOfferMessageB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      contextBindingB64u,
      code: 'server_prepare_failed',
      message,
    };
  }
}

export async function respondThresholdEd25519HssServerCeremonyWithSession(args: {
  relayerUrl: string;
  walletSessionJwt: string;
  ceremonyHandle: string;
  contextBindingB64u: string;
  clientRequest: Pick<ThresholdEd25519HssClientRequestEnvelope, 'clientRequestMessageB64u'>;
}): Promise<RespondThresholdEd25519HssServerCeremonyWithSessionResult> {
  const contextBindingB64u = String(args.contextBindingB64u || '').trim();
  try {
    const startedAt = Date.now();
    const relayerUrl = stripTrailingSlashes(String(args.relayerUrl || '').trim());
    const walletSessionJwt = String(args.walletSessionJwt || '').trim();
    const ceremonyHandle = String(args.ceremonyHandle || '').trim();
    if (!relayerUrl) throw new Error('Missing relayerUrl for Ed25519 HSS server respond');
    if (!walletSessionJwt) {
      throw new Error('Missing Wallet Session JWT for Ed25519 HSS server respond');
    }
    if (!ceremonyHandle) throw new Error('Missing ceremonyHandle for Ed25519 HSS server respond');
    if (typeof fetch !== 'function') {
      throw new Error('fetch is not available for Ed25519 HSS server respond');
    }

    const requestPayload = {
      ceremonyHandle,
      clientRequest: {
        clientRequestMessageB64u: args.clientRequest.clientRequestMessageB64u,
      },
    };
    const serializeStartedAt = Date.now();
    const requestBody = JSON.stringify(requestPayload);
    const serializeMs = Date.now() - serializeStartedAt;
    const requestBytes = utf8Bytes(requestBody);
    const requestSizeBreakdown = summarizeRespondRequestSize({
      ceremonyHandle,
      clientRequest: args.clientRequest,
    });

    const fetchStartedAt = Date.now();
    const response = await fetch(`${relayerUrl}${ROUTER_AB_ED25519_HSS_RESPOND_PATH}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${walletSessionJwt}`,
      },
      credentials: 'omit',
      body: requestBody,
    });
    const fetchMs = Date.now() - fetchStartedAt;

    const parseStartedAt = Date.now();
    const data = (await response.json().catch(() => ({}))) as Partial<{
      ok: boolean;
      contextBindingB64u: string;
      serverInputDeliveryB64u: string;
      code: string;
      message: string;
    }>;
    const parseMs = Date.now() - parseStartedAt;
    const serverInputDeliveryB64u = String(data.serverInputDeliveryB64u || '').trim();
    const deliveryContextBindingB64u = String(data.contextBindingB64u || '').trim();
    if (!response.ok || data.ok !== true || !serverInputDeliveryB64u) {
      throw new Error(data.message || data.code || `HTTP ${response.status}`);
    }
    if (deliveryContextBindingB64u !== contextBindingB64u) {
      throw new Error('HSS server-input delivery context binding mismatch');
    }
    const responsePayload = {
      contextBindingB64u: deliveryContextBindingB64u,
      serverInputDeliveryB64u,
    };
    const responseBytes = jsonBytes(responsePayload);
    const responseSizeBreakdown = {};
    console.info('[threshold-ed25519][client] hss respond timings', {
      ceremonyHandle,
      serializeMs,
      fetchMs,
      parseMs,
      requestBytes,
      requestSizeBreakdown,
      responseBytes,
      responseSizeBreakdown,
      totalMs: Date.now() - startedAt,
    });
    return {
      ok: true,
      contextBindingB64u,
      serverInputDelivery: {
        contextBindingB64u: deliveryContextBindingB64u,
        serverInputDeliveryB64u,
      },
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      contextBindingB64u,
      code: 'server_respond_failed',
      message,
    };
  }
}

export async function finalizeThresholdEd25519HssServerCeremonyWithSession(args: {
  relayerUrl: string;
  walletSessionJwt: string;
  ceremonyHandle: string;
  contextBindingB64u: string;
  evaluationResult: ThresholdEd25519HssStagedEvaluatorArtifactEnvelope;
}): Promise<FinalizeThresholdEd25519HssServerCeremonyWithSessionResult> {
  const contextBindingB64u = String(args.contextBindingB64u || '').trim();
  try {
    const startedAt = Date.now();
    const relayerUrl = stripTrailingSlashes(String(args.relayerUrl || '').trim());
    const walletSessionJwt = String(args.walletSessionJwt || '').trim();
    const ceremonyHandle = String(args.ceremonyHandle || '').trim();
    if (!relayerUrl) throw new Error('Missing relayerUrl for Ed25519 HSS server finalize');
    if (!walletSessionJwt) {
      throw new Error('Missing Wallet Session JWT for Ed25519 HSS server finalize');
    }
    if (!ceremonyHandle) throw new Error('Missing ceremonyHandle for Ed25519 HSS server finalize');
    if (typeof fetch !== 'function') {
      throw new Error('fetch is not available for Ed25519 HSS server finalize');
    }

    const requestPayload = {
      ceremonyHandle,
      evaluationResult: args.evaluationResult,
    };
    const serializeStartedAt = Date.now();
    const requestBody = JSON.stringify(requestPayload);
    const serializeMs = Date.now() - serializeStartedAt;
    const requestBytes = utf8Bytes(requestBody);
    const requestSizeBreakdown = {
      ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
    };

    const fetchStartedAt = Date.now();
    const response = await fetch(`${relayerUrl}${ROUTER_AB_ED25519_HSS_FINALIZE_PATH}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${walletSessionJwt}`,
      },
      credentials: 'omit',
      body: requestBody,
    });
    const fetchMs = Date.now() - fetchStartedAt;

    const parseStartedAt = Date.now();
    const data = (await response.json().catch(() => ({}))) as Partial<{
      ok: boolean;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
      code: string;
      message: string;
    }>;
    const parseMs = Date.now() - parseStartedAt;
    if (!response.ok || data.ok !== true || !data.finalizedReport) {
      throw new Error(data.message || data.code || `HTTP ${response.status}`);
    }
    if (String(data.finalizedReport.contextBindingB64u || '').trim() !== contextBindingB64u) {
      throw new Error('HSS finalized report context binding mismatch');
    }
    const responsePayload = {
      finalizedReport: data.finalizedReport,
    };
    const responseBytes = jsonBytes(responsePayload);
    const responseSizeBreakdown = {
      finalizedReportBytes: jsonBytes(data.finalizedReport),
      clientOutputMessageBytes: utf8Bytes(data.finalizedReport.clientOutputMessageB64u),
      seedOutputMessageBytes: utf8Bytes(String(data.finalizedReport.seedOutputMessageB64u || '')),
    };
    console.info('[threshold-ed25519][client] hss finalize timings', {
      ceremonyHandle,
      serializeMs,
      fetchMs,
      parseMs,
      requestBytes,
      requestSizeBreakdown,
      responseBytes,
      responseSizeBreakdown,
      totalMs: Date.now() - startedAt,
    });
    return {
      ok: true,
      contextBindingB64u,
      finalizedReport: data.finalizedReport,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      contextBindingB64u,
      code: 'server_finalize_failed',
      message,
    };
  }
}

export async function runThresholdEd25519HssCeremonyWithSession(args: {
  relayerUrl: string;
  walletSessionJwt: string;
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  context: ThresholdEd25519HssCanonicalContext;
  clientInputs: ThresholdEd25519HssClientInputs;
  outputProjection: ThresholdEd25519HssOutputProjectionPolicy;
  workerCtx: WorkerOperationContext;
}): Promise<CompleteThresholdEd25519HssClientCeremonyResult> {
  validateThresholdEd25519HssOutputProjectionPolicy(args.outputProjection);
  const startedAt = Date.now();
  const prepared = await prepareThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    relayerKeyId: args.relayerKeyId,
    operation: args.operation,
    context: args.context,
  });
  if (!prepared.ok) {
    return {
      ok: false,
      contextBindingB64u: prepared.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: prepared.message,
    };
  }

  const clientOutputMaskHandle = await prepareClientOwnedEvaluatorMaskHandle({
    outputProjection: args.outputProjection,
    context: args.context,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    operation: clientOutputMaskOperationForSessionOperation(args.operation),
    relayerKeyId: args.relayerKeyId,
    workerCtx: args.workerCtx,
  });
  const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
    evaluatorDriverStateB64u: prepared.preparedSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
    clientInputs: args.clientInputs,
    workerCtx: args.workerCtx,
  });

  const responded = await respondThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    ceremonyHandle: prepared.ceremonyHandle,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    clientRequest,
  });
  if (!responded.ok) {
    return {
      ok: false,
      contextBindingB64u: responded.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: responded.message,
    };
  }

  const evaluateStartedAt = Date.now();
  const evaluationResult =
    await buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm({
    preparedSession: prepared.preparedSession,
    clientRequest,
    serverInputDelivery: responded.serverInputDelivery,
    clientOutputMaskHandle,
    expectedContextBindingB64u: prepared.preparedSession.contextBindingB64u,
    addStageVerification: 'skip',
    workerCtx: args.workerCtx,
  });
  if (evaluationResult.contextBindingB64u !== prepared.preparedSession.contextBindingB64u) {
    return {
      ok: false,
      contextBindingB64u: evaluationResult.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: 'HSS client-owned staged artifact context binding mismatch',
    };
  }
  const evaluateMs = Date.now() - evaluateStartedAt;

  const finalized = await finalizeThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    ceremonyHandle: prepared.ceremonyHandle,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    evaluationResult,
  });
  if (!finalized.ok) {
    return {
      ok: false,
      contextBindingB64u: finalized.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: finalized.message,
    };
  }

  console.info('[threshold-ed25519][client] hss ceremony timings', {
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    evaluateMs,
    totalMs: Date.now() - startedAt,
  });
  return {
    ok: true,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    preparedSession: prepared.preparedSession,
    finalizedReport: finalized.finalizedReport,
  };
}

export async function runThresholdEd25519HssCeremonyWithMaterialHandle(args: {
  relayerUrl: string;
  walletSessionJwt: string;
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  clientOutputMaskOperation: ThresholdEd25519HssClientOutputMaskOperation;
  context: ThresholdEd25519HssCanonicalContext;
  clientInputs: ThresholdEd25519HssClientInputs;
  outputProjection: ThresholdEd25519HssOutputProjectionPolicy;
  materialBinding: {
    thresholdSessionId: string;
    signingGrantId: string;
    signingRootId: string;
    signingRootVersion: string;
    expiresAtMs: number;
    nearAccountId: string;
    signerSlot: number;
    relayerKeyId: string;
    participantIds: number[];
    createdAtMs: number;
    signingWorkerId: string;
  };
  preparedSealAuthorization: ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult;
  workerCtx: WorkerOperationContext;
}): Promise<CompleteThresholdEd25519HssMaterialHandleCeremonyResult> {
  validateThresholdEd25519HssOutputProjectionPolicy(args.outputProjection);
  const startedAt = Date.now();
  const prepared = await prepareThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    relayerKeyId: args.relayerKeyId,
    operation: args.operation,
    context: args.context,
  });
  if (!prepared.ok) {
    return {
      ok: false,
      contextBindingB64u: prepared.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: prepared.message,
    };
  }

  const evaluatorClientOutputMaskHandle = await prepareClientOwnedEvaluatorMaskHandle({
    outputProjection: args.outputProjection,
    context: args.context,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    operation: args.clientOutputMaskOperation,
    relayerKeyId: args.relayerKeyId,
    workerCtx: args.workerCtx,
  });
  const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
    evaluatorDriverStateB64u: prepared.preparedSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
    clientInputs: args.clientInputs,
    workerCtx: args.workerCtx,
  });

  const responded = await respondThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    ceremonyHandle: prepared.ceremonyHandle,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    clientRequest,
  });
  if (!responded.ok) {
    return {
      ok: false,
      contextBindingB64u: responded.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: responded.message,
    };
  }

  const evaluateStartedAt = Date.now();
  const evaluationResult =
    await buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm({
      preparedSession: prepared.preparedSession,
      clientRequest,
      serverInputDelivery: responded.serverInputDelivery,
      clientOutputMaskHandle: evaluatorClientOutputMaskHandle,
      expectedContextBindingB64u: prepared.preparedSession.contextBindingB64u,
      addStageVerification: 'skip',
      workerCtx: args.workerCtx,
    });
  if (evaluationResult.contextBindingB64u !== prepared.preparedSession.contextBindingB64u) {
    return {
      ok: false,
      contextBindingB64u: evaluationResult.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: 'HSS client-owned staged artifact context binding mismatch',
    };
  }
  const evaluateMs = Date.now() - evaluateStartedAt;

  const finalized = await finalizeThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    walletSessionJwt: args.walletSessionJwt,
    ceremonyHandle: prepared.ceremonyHandle,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    evaluationResult,
  });
  if (!finalized.ok) {
    return {
      ok: false,
      contextBindingB64u: finalized.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: finalized.message,
    };
  }

  const clientOutputMaskHandle = await resolveThresholdEd25519HssClientOutputMaskHandle({
    policy: args.outputProjection,
    context: {
      ...args.context,
      contextBindingB64u: prepared.preparedSession.contextBindingB64u,
      operation: args.clientOutputMaskOperation,
      relayerKeyId: args.relayerKeyId,
    },
    workerCtx: args.workerCtx,
  });

  const completeStartedAt = Date.now();
  const signingMaterial = await storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm({
    evaluatorDriverStateB64u: prepared.preparedSession.evaluatorDriverStateB64u,
    clientOutputMessageB64u: finalized.finalizedReport.clientOutputMessageB64u,
    clientOutputMaskHandle,
    expectedContextBindingB64u: prepared.preparedSession.contextBindingB64u,
    nearAccountId: args.materialBinding.nearAccountId,
    signerSlot: args.materialBinding.signerSlot,
    signingRootId: args.materialBinding.signingRootId,
    signingRootVersion: args.materialBinding.signingRootVersion,
    relayerKeyId: args.materialBinding.relayerKeyId,
    participantIds: args.materialBinding.participantIds,
    createdAtMs: args.materialBinding.createdAtMs,
    sealAuthorization: args.preparedSealAuthorization.sealAuthorization,
    workerCtx: args.workerCtx,
  });
  if (!signingMaterial.ok) {
    return {
      ok: false,
      contextBindingB64u: prepared.preparedSession.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: signingMaterial.message,
    };
  }
  if (signingMaterial.materialKeyId !== args.preparedSealAuthorization.materialKeyId) {
    return {
      ok: false,
      contextBindingB64u: prepared.preparedSession.contextBindingB64u,
      code: 'complete_client_ceremony_failed',
      message: 'HSS worker material key id mismatch after store',
    };
  }
  const completeMs = Date.now() - completeStartedAt;
  console.info('[threshold-ed25519][client] hss material-handle ceremony timings', {
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    evaluateMs,
    completeMs,
    totalMs: Date.now() - startedAt,
  });
  return {
    ok: true,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    preparedSession: prepared.preparedSession,
    finalizedReport: finalized.finalizedReport,
    signingMaterial,
  };
}

export async function storeThresholdEd25519WorkerMaterialFromFinalizedHssReport(args: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  clientOutputMask: {
    policy: ThresholdEd25519HssOutputProjectionPolicy;
    context: ThresholdEd25519HssClientOutputMaskContext;
  };
  materialBinding: {
    thresholdSessionId: string;
    signingGrantId: string;
    signingRootId: string;
    signingRootVersion: string;
    expiresAtMs: number;
    nearAccountId: string;
    signerSlot: number;
    relayerKeyId: string;
    participantIds: number[];
    createdAtMs: number;
    signingWorkerId: string;
  };
  preparedSealAuthorization: ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult;
  workerCtx: WorkerOperationContext;
}): Promise<StoreThresholdEd25519WorkerMaterialFromFinalizedHssReportResult> {
  const contextBindingB64u = String(args.preparedSession.contextBindingB64u || '').trim();
  try {
    if (!contextBindingB64u) {
      throw new Error('HSS prepared session is missing context binding');
    }
    if (String(args.finalizedReport.contextBindingB64u || '').trim() !== contextBindingB64u) {
      throw new Error('HSS finalized report context binding mismatch');
    }
    const clientOutputMessageB64u = String(args.finalizedReport.clientOutputMessageB64u || '').trim();
    if (!clientOutputMessageB64u) {
      throw new Error('HSS finalized report is missing client output');
    }
    const clientOutputMaskHandle = await resolveThresholdEd25519HssClientOutputMaskHandle({
      policy: args.clientOutputMask.policy,
      context: args.clientOutputMask.context,
      workerCtx: args.workerCtx,
    });
    const signingMaterial = await storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm({
      evaluatorDriverStateB64u: args.preparedSession.evaluatorDriverStateB64u,
      clientOutputMessageB64u,
      clientOutputMaskHandle,
      expectedContextBindingB64u: contextBindingB64u,
      nearAccountId: args.materialBinding.nearAccountId,
      signerSlot: args.materialBinding.signerSlot,
      signingRootId: args.materialBinding.signingRootId,
      signingRootVersion: args.materialBinding.signingRootVersion,
      relayerKeyId: args.materialBinding.relayerKeyId,
      participantIds: args.materialBinding.participantIds,
      createdAtMs: args.materialBinding.createdAtMs,
      sealAuthorization: args.preparedSealAuthorization.sealAuthorization,
      workerCtx: args.workerCtx,
    });
    if (!signingMaterial.ok) {
      return {
        ok: false,
        contextBindingB64u,
        code: 'store_worker_material_failed',
        message: signingMaterial.message,
      };
    }
    if (signingMaterial.materialKeyId !== args.preparedSealAuthorization.materialKeyId) {
      return {
        ok: false,
        contextBindingB64u,
        code: 'store_worker_material_failed',
        message: 'HSS worker material key id mismatch after store',
      };
    }
    return {
      ok: true,
      contextBindingB64u,
      signingMaterial,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      contextBindingB64u,
      code: 'store_worker_material_failed',
      message,
    };
  }
}

export async function openThresholdEd25519HssSeedOutput(args: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  workerCtx: WorkerOperationContext;
}): Promise<OpenThresholdEd25519HssSeedOutputResult> {
  const contextBindingB64u = String(args.preparedSession.contextBindingB64u || '').trim();
  try {
    if (String(args.finalizedReport.contextBindingB64u || '').trim() !== contextBindingB64u) {
      throw new Error('HSS finalized report context binding mismatch');
    }
    if (!String(args.finalizedReport.seedOutputMessageB64u || '').trim()) {
      throw new Error('HSS finalized report is missing seed output');
    }

    const seedOutput = await openThresholdEd25519HssSeedOutputWasm({
      preparedSession: args.preparedSession,
      finalizedReport: {
        seedOutputMessageB64u: String(args.finalizedReport.seedOutputMessageB64u || '').trim(),
      },
      workerCtx: args.workerCtx,
    });

    if (seedOutput.contextBindingB64u !== contextBindingB64u) {
      throw new Error('HSS seed output context binding mismatch');
    }

    return {
      ok: true,
      contextBindingB64u,
      seedOutput,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      contextBindingB64u,
      code: 'open_seed_output_failed',
      message,
    };
  }
}

export async function buildThresholdEd25519SeedExportArtifactFromHssReport(args: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  expectedPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<BuildThresholdEd25519SeedExportArtifactResult> {
  const seedResult = await openThresholdEd25519HssSeedOutput({
    preparedSession: args.preparedSession,
    finalizedReport: args.finalizedReport,
    workerCtx: args.workerCtx,
  });
  if (!seedResult.ok) {
    return {
      ok: false,
      contextBindingB64u: seedResult.contextBindingB64u,
      code: seedResult.code,
      message: seedResult.message,
    };
  }

  try {
    const artifact = await buildThresholdEd25519SeedExportArtifactWasm({
      seedB64u: seedResult.seedOutput.canonicalSeedB64u,
      expectedPublicKey: String(args.expectedPublicKey || '').trim(),
      workerCtx: args.workerCtx,
    });
    return {
      ok: true,
      contextBindingB64u: seedResult.contextBindingB64u,
      seedOutput: seedResult.seedOutput,
      artifact,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      ok: false,
      contextBindingB64u: seedResult.contextBindingB64u,
      code: 'build_seed_export_artifact_failed',
      message,
    };
  }
}
