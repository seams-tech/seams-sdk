import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoActiveClientStatusV1,
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';

type ActiveClientLifecycle =
  | { kind: 'active'; handle: string }
  | { kind: 'disposed'; handle?: never };

function requireNonEmpty(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function cloneMetadata(
  metadata: RouterAbEd25519YaoActiveClientMetadataV1,
): RouterAbEd25519YaoActiveClientMetadataV1 {
  return {
    kind: metadata.kind,
    scope: {
      lifecycle_id: metadata.scope.lifecycle_id,
      root_share_epoch: metadata.scope.root_share_epoch,
      account_id: metadata.scope.account_id,
      threshold_session_id: metadata.scope.threshold_session_id,
      signer_set_id: metadata.scope.signer_set_id,
      signing_worker_id: metadata.scope.signing_worker_id,
      material_activation: metadata.scope.material_activation,
    },
    applicationBinding: {
      wallet_id: metadata.applicationBinding.wallet_id,
      near_ed25519_signing_key_id: metadata.applicationBinding.near_ed25519_signing_key_id,
      signing_root_id: metadata.applicationBinding.signing_root_id,
      key_creation_signer_slot: metadata.applicationBinding.key_creation_signer_slot,
    },
    participantIds: [metadata.participantIds[0], metadata.participantIds[1]],
    registeredPublicKey: metadata.registeredPublicKey.slice(),
    signingWorkerVerifyingShare: metadata.signingWorkerVerifyingShare.slice(),
    stateEpoch: metadata.stateEpoch,
    transcript: metadata.transcript.slice(),
    activeCapabilityBinding: [...metadata.activeCapabilityBinding],
    materialActivation: metadata.materialActivation,
  };
}

function activeHandle(lifecycle: ActiveClientLifecycle): string {
  if (lifecycle.kind === 'active') return lifecycle.handle;
  throw new Error('Wallet custody Ed25519 active client is disposed');
}

function scheduleDisposal(args: {
  workerContext: WorkerOperationContext;
  handle: string;
}): void {
  void args.workerContext
    .requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'disposeEmailOtpEd25519YaoActiveClient',
        payload: { activeClientHandle: args.handle },
      },
    })
    .catch(() => undefined);
}

export async function disposeWalletCustodyEd25519ActiveClientV1(args: {
  workerContext: WorkerOperationContext;
  activeClientHandle: string;
}): Promise<boolean> {
  const result = await args.workerContext.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'disposeEmailOtpEd25519YaoActiveClient',
      payload: {
        activeClientHandle: requireNonEmpty(args.activeClientHandle, 'activeClientHandle'),
      },
    },
  });
  return result.removed;
}

/**
 * The worker owns the opened custody material. The browser only keeps this
 * opaque handle while the active signing lane is registered.
 */
export class WalletCustodyEd25519ActiveClientV1 implements RouterAbEd25519YaoActiveClientV1 {
  private lifecycle: ActiveClientLifecycle;
  private readonly activeMetadata: RouterAbEd25519YaoActiveClientMetadataV1;

  constructor(
    private readonly workerContext: WorkerOperationContext,
    activeClientHandle: string,
    metadata: RouterAbEd25519YaoActiveClientMetadataV1,
  ) {
    this.lifecycle = {
      kind: 'active',
      handle: requireNonEmpty(activeClientHandle, 'activeClientHandle'),
    };
    this.activeMetadata = cloneMetadata(metadata);
  }

  async createSigningShare(
    input: RouterAbEd25519YaoClientSigningInputV1,
  ): Promise<RouterAbEd25519YaoClientSigningShareV1> {
    return await this.workerContext.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'createEmailOtpEd25519YaoSigningShare',
        payload: { activeClientHandle: activeHandle(this.lifecycle), input },
      },
    });
  }

  metadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
    return cloneMetadata(this.activeMetadata);
  }

  status(): RouterAbEd25519YaoActiveClientStatusV1 {
    return this.lifecycle.kind === 'active' ? { kind: 'active' } : { kind: 'disposed' };
  }

  dispose(): void {
    if (this.lifecycle.kind !== 'active') return;
    const handle = this.lifecycle.handle;
    this.lifecycle = { kind: 'disposed' };
    scheduleDisposal({ workerContext: this.workerContext, handle });
  }
}
