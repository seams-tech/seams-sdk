import type { TransactionContext } from '@/core/types/rpc';
import type { RouterAbNormalSigningPrepareRequestV2BuildResult } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { CapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import { computeCapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type {
  NearOperationStepUpPreparationPort,
  NearOperationStepUpPreparationRef,
} from '@/core/signingEngine/interfaces/operationStepUpPreparation';
import { parseNearOperationStepUpPreparationRef } from '@/core/signingEngine/interfaces/operationStepUpPreparation';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';

type PreparedNearOperationStepUpBase = {
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
  signingDigestB64u: string;
  materialActivation: MpcMaterialActivationRef;
};

export type PreparedNearOperationStepUp =
  | (PreparedNearOperationStepUpBase & {
      kind: 'near_transaction';
      unsignedTransactionBorshB64u: string;
    })
  | (PreparedNearOperationStepUpBase & {
      kind: 'near_signature_only';
      unsignedTransactionBorshB64u?: never;
    });

export type NearOperationStepUpBuilderInput =
  | {
      kind: 'near_transaction';
      transactionContext: TransactionContext;
      operationId: string;
      operationFingerprint: string;
      displayDigest: string;
    }
  | {
      kind: 'near_signature_only';
      displayDigest: string;
      transactionContext?: never;
      operationId?: never;
      operationFingerprint?: never;
    };

type PreparedNearOperationStepUpBuilder = (input: NearOperationStepUpBuilderInput) => Promise<{
  operation: PreparedNearOperationStepUp;
  envelope: CapabilityOperationEnvelope;
}>;

const pendingBuilders = new Map<string, PreparedNearOperationStepUpBuilder>();
const preparedOperations = new Map<
  string,
  { requestId: string; operation: PreparedNearOperationStepUp }
>();

function requirePreparationIdentity(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`[SigningEngine][near] ${field} is required`);
  return normalized;
}

export function registerNearOperationStepUpBuilder(input: {
  requestId: string;
  build: PreparedNearOperationStepUpBuilder;
}): void {
  pendingBuilders.set(requirePreparationIdentity(input.requestId, 'requestId'), input.build);
}

export function clearNearOperationStepUpBuilder(requestId: string): void {
  pendingBuilders.delete(String(requestId || '').trim());
}

export const nearOperationStepUpPreparationPort: NearOperationStepUpPreparationPort = {
  async prepare(input): Promise<NearOperationStepUpPreparationRef> {
    const requestId = requirePreparationIdentity(input.requestId, 'requestId');
    const builder = pendingBuilders.get(requestId);
    if (!builder) {
      throw new Error('[SigningEngine][near] operation step-up preparation is unavailable');
    }
    pendingBuilders.delete(requestId);
    const prepared =
      input.kind === 'near_transaction'
        ? await builder({
            kind: 'near_transaction',
            transactionContext: input.transactionContext,
            operationId: requirePreparationIdentity(input.operationId, 'operationId'),
            operationFingerprint: requirePreparationIdentity(
              input.operationFingerprint,
              'operationFingerprint',
            ),
            displayDigest: requirePreparationIdentity(input.displayDigest, 'displayDigest'),
          })
        : await builder({
            kind: 'near_signature_only',
            displayDigest: requirePreparationIdentity(input.displayDigest, 'displayDigest'),
          });
    const challengeB64u = await computeCapabilityOperationFingerprintDigest(prepared.envelope);
    const ref = parseNearOperationStepUpPreparationRef({
      kind: 'near_operation_step_up_prepared_v1',
      handle: `near-operation-step-up:${secureRandomBase64Url(24, 'operation step-up handle')}`,
      challengeB64u,
    });
    preparedOperations.set(ref.handle, { requestId, operation: prepared.operation });
    return ref;
  },
  cancel(input): void {
    const requestId = String(input.requestId || '').trim();
    if (requestId) pendingBuilders.delete(requestId);
    if (input.handle) preparedOperations.delete(input.handle);
    for (const [handle, prepared] of preparedOperations) {
      if (prepared.requestId === requestId) preparedOperations.delete(handle);
    }
  },
};

export function consumePreparedNearOperationStepUp(input: {
  requestId: string;
  ref: NearOperationStepUpPreparationRef;
}): PreparedNearOperationStepUp {
  const requestId = requirePreparationIdentity(input.requestId, 'requestId');
  const ref = parseNearOperationStepUpPreparationRef(input.ref);
  const handle = requirePreparationIdentity(ref.handle, 'operation step-up handle');
  const prepared = preparedOperations.get(handle);
  preparedOperations.delete(handle);
  if (!prepared || prepared.requestId !== requestId) {
    throw new Error('[SigningEngine][near] prepared operation step-up is unavailable');
  }
  return prepared.operation;
}

export function requireNearOperationStepUpMaterialActivation(args: {
  expected: MpcMaterialActivationRef;
  actual: MpcMaterialActivationRef;
}): void {
  if (!mpcMaterialActivationRefsEqual(args.expected, args.actual)) {
    throw new Error('[SigningEngine][near] operation assertion changed material activation');
  }
}
