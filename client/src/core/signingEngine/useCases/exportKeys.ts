import { thresholdEcdsaChainTargetsEqual } from '../interfaces/ecdsaChainTarget';
import {
  useCaseFailure,
  type ExportKeyArtifact,
  type ExportKeyRequest,
  type ExportKeysAuthorization,
  type ExportKeysFailureCode,
  type ExportKeysInput,
  type ExportKeysLifecycleState,
  type ExportKeysResult,
  type ExportKeysSuccess,
  type NonEmptyReadonlyArray,
  type ReadyEcdsaLane,
  type ReadyEd25519Lane,
  type UseCaseFailure,
} from './lifecycle';

export type ExportKeysFailure = UseCaseFailure<ExportKeysFailureCode>;

export type ExportKeysMaterial =
  | {
      request: Extract<ExportKeyRequest, { kind: 'near_ed25519' }>;
      lane: ReadyEd25519Lane;
    }
  | {
      request: Extract<ExportKeyRequest, { kind: 'ecdsa_secp256k1' }>;
      lane: ReadyEcdsaLane;
    };

type ExportKeysResolvedMaterialResult =
  | {
      ok: true;
      material: NonEmptyReadonlyArray<ExportKeysMaterial>;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | ExportKeysFailure;

type ExportKeysArtifactsResult =
  | {
      ok: true;
      artifacts: NonEmptyReadonlyArray<ExportKeyArtifact>;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | ExportKeysFailure;

export type ExportKeysMaterialLoadResult =
  | {
      ok: true;
      material: NonEmptyReadonlyArray<ReadyEd25519Lane | ReadyEcdsaLane>;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        ExportKeysFailureCode,
        'missing_requested_material' | 'invalid_ready_state' | 'storage_failed' | 'invalid_state'
      >
    >;

export type ExportKeysArtifactBuildResult =
  | {
      ok: true;
      artifact: ExportKeyArtifact;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        ExportKeysFailureCode,
        | 'missing_requested_material'
        | 'invalid_ready_state'
        | 'signer_crypto_command_failed'
        | 'signer_crypto_invocation_failed'
        | 'relayer_failed'
        | 'storage_failed'
        | 'invalid_state'
      >
    >;

export type ExportKeysViewerOpenResult =
  | {
      ok: true;
      viewerSessionId: string;
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<Extract<ExportKeysFailureCode, 'storage_failed' | 'invalid_state'>>;

export type ExportKeysDeps = {
  clock: {
    nowMs(): number;
  };
  materialLoader: {
    load(input: ExportKeysInput): Promise<ExportKeysMaterialLoadResult>;
  };
  artifactBuilder: {
    buildEd25519(input: {
      input: ExportKeysInput;
      request: Extract<ExportKeyRequest, { kind: 'near_ed25519' }>;
      lane: ReadyEd25519Lane;
      authorization: ExportKeysAuthorization;
    }): Promise<ExportKeysArtifactBuildResult>;
    buildEcdsa(input: {
      input: ExportKeysInput;
      request: Extract<ExportKeyRequest, { kind: 'ecdsa_secp256k1' }>;
      lane: ReadyEcdsaLane;
      authorization: ExportKeysAuthorization;
    }): Promise<ExportKeysArtifactBuildResult>;
  };
  viewer: {
    open(input: {
      input: ExportKeysInput;
      authorization: ExportKeysAuthorization;
      artifacts: NonEmptyReadonlyArray<ExportKeyArtifact>;
    }): Promise<ExportKeysViewerOpenResult>;
  };
  lifecycle?: {
    transition(state: ExportKeysLifecycleState): void | Promise<void>;
  };
};

export type ExportKeysUseCase = {
  export(input: ExportKeysInput): Promise<ExportKeysResult>;
};

export function createExportKeysUseCase(deps: ExportKeysDeps): ExportKeysUseCase {
  return {
    export: (input) => exportKeys(deps, input),
  };
}

function toNonEmptyReadonlyArray<T>(items: readonly T[]): NonEmptyReadonlyArray<T> | null {
  const first = items[0];
  if (first === undefined) return null;
  return [first, ...items.slice(1)];
}

function failure(input: {
  code: ExportKeysFailureCode;
  source: ExportKeysFailure['source'];
  message: string;
  retryable: boolean;
  cause?: unknown;
}): ExportKeysFailure {
  return useCaseFailure(input);
}

async function emit(deps: ExportKeysDeps, state: ExportKeysLifecycleState): Promise<void> {
  await deps.lifecycle?.transition(state);
}

async function emitFailure(
  deps: ExportKeysDeps,
  result: ExportKeysFailure,
): Promise<ExportKeysFailure> {
  await emit(deps, {
    kind: 'failed',
    ok: false,
    code: result.code,
    source: result.source,
    message: result.message,
    retryable: result.retryable,
    ...(result.cause === undefined ? {} : { cause: result.cause }),
  });
  return result;
}

function requestKey(request: ExportKeyRequest): string {
  switch (request.kind) {
    case 'near_ed25519':
      return 'near_ed25519';
    case 'ecdsa_secp256k1':
      return `ecdsa_secp256k1:${JSON.stringify(request.chainTarget)}`;
  }
}

function hasDuplicateRequests(requests: NonEmptyReadonlyArray<ExportKeyRequest>): boolean {
  const seen = new Set<string>();
  for (const request of requests) {
    const key = requestKey(request);
    if (seen.has(key)) return true;
    seen.add(key);
  }
  return false;
}

function isEd25519ExportMaterial(
  material: ExportKeysMaterial,
): material is Extract<ExportKeysMaterial, { request: { kind: 'near_ed25519' } }> {
  return material.request.kind === 'near_ed25519';
}

function isEcdsaExportMaterial(
  material: ExportKeysMaterial,
): material is Extract<ExportKeysMaterial, { request: { kind: 'ecdsa_secp256k1' } }> {
  return material.request.kind === 'ecdsa_secp256k1';
}

function scopeCoversRequest(
  authorization: ExportKeysAuthorization,
  request: ExportKeyRequest,
): boolean {
  return authorization.scopes.some((scope) => {
    switch (request.kind) {
      case 'near_ed25519':
        return (
          scope.kind === 'ed25519_export_scope' &&
          scope.curve === 'ed25519' &&
          scope.chain === 'near'
        );
      case 'ecdsa_secp256k1':
        return (
          scope.kind === 'ecdsa_export_scope' &&
          scope.curve === 'ecdsa' &&
          thresholdEcdsaChainTargetsEqual(scope.chainTarget, request.chainTarget)
        );
    }
  });
}

function validateAuthorization(args: {
  input: ExportKeysInput;
  nowMs: number;
}): ExportKeysFailure | null {
  const { input, nowMs } = args;
  const authorization = input.authorization;
  if (
    String(authorization.walletId) !== String(input.walletId) ||
    String(authorization.rpId) !== String(input.rpId)
  ) {
    return failure({
      code: 'authorization_failed',
      source: 'domain',
      message: 'Export authorization does not match wallet and RP',
      retryable: false,
    });
  }
  if (
    !Number.isFinite(nowMs) ||
    !Number.isFinite(authorization.issuedAtMs) ||
    !Number.isFinite(authorization.expiresAtMs) ||
    authorization.expiresAtMs <= authorization.issuedAtMs ||
    authorization.expiresAtMs <= nowMs
  ) {
    return failure({
      code: 'authorization_failed',
      source: 'clock',
      message: 'Export authorization is expired or malformed',
      retryable: true,
    });
  }
  if (hasDuplicateRequests(input.requestedKeys)) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'Export requested the same key more than once',
      retryable: false,
    });
  }
  const missingScope = input.requestedKeys.find(
    (request) => !scopeCoversRequest(authorization, request),
  );
  if (missingScope) {
    return failure({
      code: 'authorization_failed',
      source: 'domain',
      message: 'Export authorization scope does not cover every requested key',
      retryable: false,
    });
  }
  return null;
}

function isReadyStateEnvelopeValid(lane: ReadyEcdsaLane): boolean {
  const blob = lane.readyRecord.stateBlob;
  return (
    blob.kind === 'ecdsa_role_local_state_blob_v1' &&
    blob.curve === 'secp256k1' &&
    blob.encoding === 'base64url' &&
    blob.producer === 'signer_core' &&
    String(blob.stateBlobB64u || '').trim().length > 0
  );
}

function findMaterialForRequest(args: {
  input: ExportKeysInput;
  request: ExportKeyRequest;
  material: NonEmptyReadonlyArray<ReadyEd25519Lane | ReadyEcdsaLane>;
}): ExportKeysMaterial | ExportKeysFailure {
  const request = args.request;
  switch (request.kind) {
    case 'near_ed25519': {
      const lane = args.material.find(
        (candidate): candidate is ReadyEd25519Lane =>
          candidate.kind === 'ed25519_ready_lane_v1' &&
          String(candidate.walletId) === String(args.input.walletId) &&
          String(candidate.rpId) === String(args.input.rpId),
      );
      if (!lane) {
        return failure({
          code: 'missing_requested_material',
          source: 'storage',
          message: 'Requested Ed25519 export material is unavailable',
          retryable: true,
        });
      }
      return { request, lane };
    }
    case 'ecdsa_secp256k1': {
      const lane = args.material.find(
        (candidate): candidate is ReadyEcdsaLane =>
          candidate.kind === 'ecdsa_ready_lane_v1' &&
          String(candidate.walletId) === String(args.input.walletId) &&
          String(candidate.rpId) === String(args.input.rpId) &&
          thresholdEcdsaChainTargetsEqual(candidate.chainTarget, request.chainTarget),
      );
      if (!lane) {
        return failure({
          code: 'missing_requested_material',
          source: 'storage',
          message: 'Requested ECDSA export material is unavailable',
          retryable: true,
        });
      }
      if (
        !isReadyStateEnvelopeValid(lane) ||
        String(lane.readyRecord.publicFacts.walletId) !== String(args.input.walletId) ||
        String(lane.readyRecord.publicFacts.rpId) !== String(args.input.rpId) ||
        !thresholdEcdsaChainTargetsEqual(
          lane.readyRecord.publicFacts.chainTarget,
          request.chainTarget,
        )
      ) {
        return failure({
          code: 'invalid_ready_state',
          source: 'storage',
          message: 'Requested ECDSA export material has invalid ready-state identity',
          retryable: false,
        });
      }
      return { request, lane };
    }
  }
}

function resolveMaterial(args: {
  input: ExportKeysInput;
  material: NonEmptyReadonlyArray<ReadyEd25519Lane | ReadyEcdsaLane>;
}): ExportKeysResolvedMaterialResult {
  const resolved: ExportKeysMaterial[] = [];
  for (const request of args.input.requestedKeys) {
    const material = findMaterialForRequest({
      input: args.input,
      request,
      material: args.material,
    });
    if ('ok' in material) return material;
    resolved.push(material);
  }
  const nonEmpty = toNonEmptyReadonlyArray(resolved);
  if (!nonEmpty) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'Export material resolution returned no material',
      retryable: false,
    });
  }
  return { ok: true, material: nonEmpty };
}

function validateArtifact(args: {
  input: ExportKeysInput;
  material: ExportKeysMaterial;
  artifact: ExportKeyArtifact;
}): ExportKeysFailure | null {
  if (String(args.artifact.walletId) !== String(args.input.walletId)) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'Export artifact wallet does not match request',
      retryable: false,
    });
  }
  if (isEd25519ExportMaterial(args.material)) {
    if (args.artifact.kind === 'near_ed25519_export_artifact_v1') return null;
  }
  if (isEcdsaExportMaterial(args.material)) {
    if (
      args.artifact.kind === 'ecdsa_secp256k1_export_artifact_v1' &&
      thresholdEcdsaChainTargetsEqual(
        args.artifact.chainTarget,
        args.material.request.chainTarget,
      ) &&
      thresholdEcdsaChainTargetsEqual(
        args.artifact.publicFacts.chainTarget,
        args.material.lane.readyRecord.publicFacts.chainTarget,
      )
    ) {
      return null;
    }
  }
  return failure({
    code: 'invalid_state',
    source: 'domain',
    message: 'Export artifact does not match requested key branch',
    retryable: false,
  });
}

async function buildArtifact(args: {
  deps: ExportKeysDeps;
  input: ExportKeysInput;
  material: ExportKeysMaterial;
}): Promise<ExportKeysArtifactBuildResult> {
  if (isEd25519ExportMaterial(args.material)) {
    return args.deps.artifactBuilder.buildEd25519({
      input: args.input,
      request: args.material.request,
      lane: args.material.lane,
      authorization: args.input.authorization,
    });
  }
  return args.deps.artifactBuilder.buildEcdsa({
    input: args.input,
    request: args.material.request,
    lane: args.material.lane,
    authorization: args.input.authorization,
  });
}

async function buildArtifacts(args: {
  deps: ExportKeysDeps;
  input: ExportKeysInput;
  material: NonEmptyReadonlyArray<ExportKeysMaterial>;
}): Promise<ExportKeysArtifactsResult> {
  const artifacts: ExportKeyArtifact[] = [];
  for (const material of args.material) {
    const built = await buildArtifact({ deps: args.deps, input: args.input, material });
    if (!built.ok) return built;
    const artifactMismatch = validateArtifact({
      input: args.input,
      material,
      artifact: built.artifact,
    });
    if (artifactMismatch) return artifactMismatch;
    artifacts.push(built.artifact);
  }
  const nonEmpty = toNonEmptyReadonlyArray(artifacts);
  if (!nonEmpty) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'Export artifact build returned no artifacts',
      retryable: false,
    });
  }
  return { ok: true, artifacts: nonEmpty };
}

export async function exportKeys(
  deps: ExportKeysDeps,
  input: ExportKeysInput,
): Promise<ExportKeysResult> {
  await emit(deps, { kind: 'received_input', ...input });

  await emit(deps, { kind: 'validating_authorization', input });
  const authorizationFailure = validateAuthorization({ input, nowMs: deps.clock.nowMs() });
  if (authorizationFailure) return emitFailure(deps, authorizationFailure);

  await emit(deps, { kind: 'loading_material', input });
  const loaded = await deps.materialLoader.load(input);
  if (!loaded.ok) return emitFailure(deps, loaded);
  const material = resolveMaterial({ input, material: loaded.material });
  if (!material.ok) return emitFailure(deps, material);

  await emit(deps, {
    kind: 'building_artifacts',
    input,
    material: loaded.material,
  });
  const artifacts = await buildArtifacts({ deps, input, material: material.material });
  if (!artifacts.ok) return emitFailure(deps, artifacts);

  await emit(deps, { kind: 'opening_viewer', artifacts: artifacts.artifacts });
  const viewer = await deps.viewer.open({
    input,
    authorization: input.authorization,
    artifacts: artifacts.artifacts,
  });
  if (!viewer.ok) return emitFailure(deps, viewer);

  const result: ExportKeysSuccess = {
    ok: true,
    artifacts: artifacts.artifacts,
    viewerSessionId: viewer.viewerSessionId,
  };
  await emit(deps, { kind: 'ready', result });
  return result;
}
