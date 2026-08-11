import type {
  EcdsaLaneProtocolWasmV1,
  Ed25519YaoLaneJobV1,
  WasmEd25519YaoLaneClientV1,
} from '@shared/signing-lanes';
import {
  parseLaneEnrollmentPreparationResultV1,
  parseLaneProtocolCasResultV1,
  parseLaneProtocolCommitReceiptV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  parseRouterAbEd25519YaoActivationKeysetV1,
  parseRouterAbEd25519YaoCeremonyBindingV1,
  type RouterAbEd25519YaoActivationKeysetV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
} from '@shared/utils/routerAbEd25519Yao';
import type { LaneOperationSourcePortsV1 } from '@/core/signingEngine/session/lanes/operations/ports';
import type { WalletHostManagementRequestV1 } from './walletHostOwnerAuthority';

const LANE_GATEWAY_BASE_PATH = '/internal/gateway/device-linking/v1/lanes';

type CreateEd25519LaneClientV1 = (input: {
  readonly job: Ed25519YaoLaneJobV1;
  readonly ceremonyBinding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly keyset: RouterAbEd25519YaoActivationKeysetV1;
}) => Promise<WasmEd25519YaoLaneClientV1>;

export function createWalletHostSourceLanePortsV1(input: {
  readonly request: WalletHostManagementRequestV1;
  readonly ecdsa: EcdsaLaneProtocolWasmV1;
  readonly createEd25519ClientV1: CreateEd25519LaneClientV1;
  readonly reconcileEcdsaActivationJournalV1: LaneOperationSourcePortsV1['reconcileEcdsaActivationJournalV1'];
  readonly nowMs: () => number;
}): LaneOperationSourcePortsV1 {
  const ed25519Yao = createWalletHostEd25519LaneClientV1(input);
  return {
    nowMs: input.nowMs,
    gateway: {
      prepareLaneEnrollmentV1: async (request) => {
        const response = await input.request.request({
          walletId: request.manifest.walletId,
          method: 'POST',
          canonicalPath: `${LANE_GATEWAY_BASE_PATH}/prepare`,
          body: request,
        });
        requireSuccess(response, 'prepare source lanes');
        return parseLaneEnrollmentPreparationResultV1(response.body);
      },
    },
    wasm: { ecdsa: input.ecdsa, ed25519Yao },
    protocolCommitter: {
      executeAndRecordEd25519YaoLaneV1: async (request) => {
        const response = await input.request.request({
          walletId: request.job.walletId,
          method: 'POST',
          canonicalPath: `${LANE_GATEWAY_BASE_PATH}/protocol-commit`,
          body: { curve: 'ed25519_yao', ...request },
        });
        requireSuccess(response, 'commit Ed25519 source lane');
        const result = exactRecord(response.body, [
          'curve',
          'receipt',
          'protocolCasResult',
          'responseJson',
        ]);
        if (result.curve !== 'ed25519_yao' || typeof result.responseJson !== 'string') {
          throw new Error('Ed25519 source-lane response is invalid');
        }
        return {
          receipt: parseLaneProtocolCommitReceiptV1(result.receipt),
          protocolCasResult: parseLaneProtocolCasResultV1(result.protocolCasResult),
          responseJson: result.responseJson,
        };
      },
      executeAndRecordEcdsaAdditiveLaneV1: async (request) => {
        const response = await input.request.request({
          walletId: request.job.walletId,
          method: 'POST',
          canonicalPath: `${LANE_GATEWAY_BASE_PATH}/protocol-commit`,
          body: { curve: 'ecdsa_additive', ...request },
        });
        requireSuccess(response, 'commit ECDSA source lane');
        const result = exactRecord(response.body, ['curve', 'receipt', 'protocolCasResult']);
        if (result.curve !== 'ecdsa_additive') {
          throw new Error('ECDSA source-lane response is invalid');
        }
        return {
          receipt: parseLaneProtocolCommitReceiptV1(result.receipt),
          protocolCasResult: parseLaneProtocolCasResultV1(result.protocolCasResult),
        };
      },
    },
    reconcileEcdsaActivationJournalV1: input.reconcileEcdsaActivationJournalV1,
  };
}

function createWalletHostEd25519LaneClientV1(input: {
  readonly request: WalletHostManagementRequestV1;
  readonly createEd25519ClientV1: CreateEd25519LaneClientV1;
}): WasmEd25519YaoLaneClientV1 {
  const clients = new Map<string, WasmEd25519YaoLaneClientV1>();
  return {
    prepare: async (job) => {
      const operationId = String(job.operationId);
      if (clients.has(operationId)) {
        throw new Error('Ed25519 source-lane operation is already prepared');
      }
      const ceremony = await readCeremonyBindingV1(input.request, job);
      const client = await input.createEd25519ClientV1({
        job,
        ceremonyBinding: ceremony.binding,
        keyset: ceremony.keyset,
      });
      clients.set(operationId, client);
      try {
        return await client.prepare(job);
      } catch (error: unknown) {
        clients.delete(operationId);
        throw error;
      }
    },
    complete: async (completion) => {
      const operationId = String(completion.job.operationId);
      const client = clients.get(operationId);
      if (!client) throw new Error('Ed25519 source-lane operation was not prepared');
      clients.delete(operationId);
      return await client.complete(completion);
    },
  };
}

async function readCeremonyBindingV1(
  request: WalletHostManagementRequestV1,
  job: Ed25519YaoLaneJobV1,
): Promise<{
  readonly binding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly keyset: RouterAbEd25519YaoActivationKeysetV1;
}> {
  const operationId = String(job.operationId);
  const response = await request.request({
    walletId: job.walletId,
    method: 'GET',
    canonicalPath: `${LANE_GATEWAY_BASE_PATH}/ceremony-binding?operationId=${encodeURIComponent(operationId)}`,
  });
  requireSuccess(response, 'resolve Ed25519 ceremony binding');
  const result = exactRecord(response.body, ['operationId', 'binding', 'keyset']);
  if (result.operationId !== operationId) {
    throw new Error('Ed25519 ceremony binding operation changed');
  }
  return {
    binding: parseRouterAbEd25519YaoCeremonyBindingV1(result.binding),
    keyset: parseRouterAbEd25519YaoActivationKeysetV1(result.keyset),
  };
}

function requireSuccess(
  response: { readonly status: number; readonly body: unknown },
  operation: string,
): void {
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`Wallet-host failed to ${operation}: HTTP ${response.status}`);
  }
}

function exactRecord(raw: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!isRecord(raw)) throw new Error('Source-lane response must be an object');
  const expected = new Set(fields);
  const actual = Object.keys(raw);
  if (actual.length !== expected.size || actual.some((field) => !expected.has(field))) {
    throw new Error('Source-lane response has unexpected fields');
  }
  return raw;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}
