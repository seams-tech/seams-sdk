import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from './workerTypes';

export type WorkerOperationContext = {
  requestWorkerOperation: <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }) => Promise<SignerWorkerOperationResult<K, T>>;
};

type WorkerOperationArgs<
  K extends SignerWorkerKind,
  T extends SignerWorkerOperationType<K>,
> = {
  kind: K;
  request: SignerWorkerOperationRequest<K, T>;
  ctx: WorkerOperationContext;
};

export async function executeWorkerOperation<
  K extends SignerWorkerKind,
  T extends SignerWorkerOperationType<K>,
>(args: WorkerOperationArgs<K, T>): Promise<SignerWorkerOperationResult<K, T>> {
  if (!args.ctx) {
    throw new Error(`[executeWorkerOperation] ctx is required for ${args.kind} operations`);
  }

  return args.ctx.requestWorkerOperation({
    kind: args.kind,
    request: args.request,
  });
}
