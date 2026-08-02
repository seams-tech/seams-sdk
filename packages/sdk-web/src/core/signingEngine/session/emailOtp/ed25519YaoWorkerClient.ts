import { base58Encode } from '@shared/utils/base58';
import {
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  buildMpcMaterialActivationRef,
  parseMpcMaterialActivationId,
  parseMpcLifecycleBindingRef,
} from '@shared/utils/domainIds';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { RouterAbNormalSigningPrepareRequestV2Wire } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  ProductEd25519YaoActivationReferenceV1,
  ProductEd25519YaoPendingRegistrationPortV1,
  ProductEd25519YaoRegistrationMaterialPersistenceV1,
} from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoActiveClientStatusV1,
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type {
  EmailOtpEd25519YaoIssuedOperationAuthorizationV1,
  EmailOtpEd25519YaoOperationStepUpProofV1,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
} from '@/core/signingEngine/workerManager/workerTypes';
import type {
  EmailOtpEd25519YaoPendingFactorHandle,
  EmailOtpEd25519YaoRootHandle,
  EmailOtpEd25519YaoRootScope,
} from './ed25519YaoRootVault';
import {
  emailOtpEd25519YaoRecoveryRootScopeV1,
  emailOtpEd25519YaoRegistrationRootScopeV1,
} from './ed25519YaoActivation';
import type {
  MpcMaterialActivationRef,
  ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import { requestRehydrateEmailOtpEd25519YaoOperationMaterial } from './workerRequests';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../material/nearEd25519YaoMaterialActivation';

type WorkerActiveClientLifecycle =
  | { kind: 'active'; activeClientHandle: string }
  | { kind: 'disposed'; activeClientHandle?: never };

type WorkerPendingRegistrationLifecycle =
  | { kind: 'pending'; pendingHandle: string }
  | {
      kind: 'persisting_material';
      result: Promise<RouterAbEd25519YaoActiveClientMetadataV1>;
      pendingHandle?: never;
    }
  | {
      kind: 'material_persisted';
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      pendingHandle?: never;
      result?: never;
    }
  | { kind: 'disposed'; pendingHandle?: never; result?: never };

type WorkerFactorOwnership =
  | {
      kind: 'pending_factor';
      pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
      rootHandle?: never;
    }
  | {
      kind: 'bound_root';
      rootHandle: EmailOtpEd25519YaoRootHandle;
      pendingFactorHandle?: never;
    }
  | {
      kind: 'pending_registration';
      pendingRegistrationHandle: string;
      pendingFactorHandle?: never;
      rootHandle?: never;
    }
  | {
      kind: 'consumed';
      pendingFactorHandle?: never;
      rootHandle?: never;
      pendingRegistrationHandle?: never;
    };

export type VerifiedEmailOtpEd25519YaoRegistrationWorkerInputV1 = {
  kind: 'verified_email_otp_ed25519_yao_registration_worker_input_v1';
  workerContext: WorkerOperationContext;
  pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
  walletId: string;
  providerSubject: string;
  registrationAuthorityId: string;
  /**
   * Bearer credential for this ceremony's Yao Router calls. Was the
   * registration-intent grant; Refactor 94C deletes the grant and the client
   * carries `signedSetup` across the ceremony's routes instead.
   */
  registrationBearerToken: string;
  routerOrigin: string;
  /**
   * Receives the Yao timing breakdown once the worker reports it. Email OTP
   * runs its ceremony inside the worker, so this callback is the only path by
   * which the Router's `Server-Timing` reaches the caller. Diagnostics only:
   * it never affects control flow, and a throwing sink is swallowed.
   */
  onYaoDiagnostics?: (diagnostics: EmailOtpEd25519YaoRegistrationDiagnosticsV1) => void;
};

export type EmailOtpEd25519YaoRegistrationDiagnosticsV1 = {
  routerServerTiming?: string;
  clientTimings?: { admissionMs: number; sessionCreateMs: number };
};

export type VerifiedEmailOtpEd25519YaoRecoveryWorkerInputV1 = {
  workerContext: WorkerOperationContext;
  pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
  expectedPriorMetadata: Pick<
    RouterAbEd25519YaoActiveClientMetadataV1,
    | 'kind'
    | 'scope'
    | 'applicationBinding'
    | 'participantIds'
    | 'registeredPublicKey'
    | 'stateEpoch'
    | 'materialActivation'
  >;
  providerSubject: string;
  registrationAuthorityId: string;
  routerOrigin: string;
};

export type EmailOtpEd25519YaoRecoveryContinuityMetadataV1 =
  VerifiedEmailOtpEd25519YaoRecoveryWorkerInputV1['expectedPriorMetadata'];

export function buildEmailOtpEd25519YaoRecoveryContinuityMetadataV1(
  bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1,
): EmailOtpEd25519YaoRecoveryContinuityMetadataV1 {
  const capability = bootstrap.capability;
  return {
    kind: ROUTER_AB_ED25519_YAO_ACTIVE_CLIENT_KIND_V1,
    scope: {
      lifecycle_id: 'persisted-email-otp-recovery-anchor-v1',
      root_share_epoch: capability.lifecycle.rootShareEpoch,
      account_id: capability.lifecycle.accountId,
      threshold_session_id: capability.lifecycle.thresholdSessionId,
      signer_set_id: capability.lifecycle.signerSetId,
      signing_worker_id: capability.lifecycle.signingWorkerId,
      material_activation: {
        kind: capability.materialActivation.kind,
        activation_id: capability.materialActivation.activationId,
        capability: capability.materialActivation.capability,
        material_owner: capability.materialActivation.materialOwner,
        key_binding: capability.materialActivation.keyBinding,
        lifecycle_binding: capability.materialActivation.lifecycleBinding,
        signing_worker: capability.materialActivation.signingWorker,
      },
    },
    applicationBinding: capability.applicationBinding,
    participantIds: capability.participantIds,
    registeredPublicKey: Uint8Array.from(capability.registeredPublicKey),
    stateEpoch: BigInt(capability.stateEpoch),
    materialActivation: capability.materialActivation,
  };
}

export type EmailOtpEd25519YaoWorkerRecoveryResultV1 = {
  activeClient: RouterAbEd25519YaoActiveClientV1;
  activation: RouterAbEd25519YaoRecoveryActivationReceiptV1;
};

function assertNever(value: never): never {
  throw new Error(`Unexpected Email OTP Ed25519 Yao worker lifecycle: ${String(value)}`);
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

function requireNonEmpty(value: string, label: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function equalBytes(left: ArrayLike<number>, right: ArrayLike<number>): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

function equalParticipants(
  left: readonly [number, number],
  right: readonly [number, number],
): boolean {
  return left[0] === right[0] && left[1] === right[1];
}

function equalRuntimePolicyScope(
  left: EmailOtpEd25519YaoRecoveryBootstrapV1['session']['runtimePolicyScope'],
  right: EmailOtpEd25519YaoRecoveryBootstrapV1['capability']['runtimePolicyScope'],
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function assertPriorRecoveryContinuity(
  input: VerifiedEmailOtpEd25519YaoRecoveryWorkerInputV1,
): void {
  const bootstrap = input.bootstrap;
  const session = bootstrap.session;
  const capability = bootstrap.capability;
  const prior = input.expectedPriorMetadata;
  const walletId = String(session.walletId);
  if (
    session.authorityScope.kind !== 'email_otp' ||
    session.authorityScope.providerUserId !== input.providerSubject ||
    capability.applicationBinding.wallet_id !== walletId ||
    capability.nearAccountId !== session.nearAccountId ||
    capability.applicationBinding.near_ed25519_signing_key_id !== session.nearEd25519SigningKeyId ||
    capability.applicationBinding.signing_root_id !== session.signingRootId ||
    capability.lifecycle.rootShareEpoch !== session.signingRootVersion ||
    capability.lifecycle.accountId !== walletId ||
    capability.lifecycle.thresholdSessionId !== session.thresholdSessionId ||
    capability.lifecycle.signingWorkerId !== session.routerAbNormalSigning.signingWorkerId ||
    !equalParticipants(capability.participantIds, session.participantIds) ||
    !equalRuntimePolicyScope(session.runtimePolicyScope, capability.runtimePolicyScope) ||
    !equalBytes(prior.registeredPublicKey, capability.registeredPublicKey) ||
    prior.applicationBinding.wallet_id !== capability.applicationBinding.wallet_id ||
    prior.applicationBinding.near_ed25519_signing_key_id !==
      capability.applicationBinding.near_ed25519_signing_key_id ||
    prior.applicationBinding.signing_root_id !== capability.applicationBinding.signing_root_id ||
    prior.applicationBinding.key_creation_signer_slot !==
      capability.applicationBinding.key_creation_signer_slot ||
    !equalParticipants(prior.participantIds, capability.participantIds) ||
    prior.scope.root_share_epoch !== capability.lifecycle.rootShareEpoch ||
    prior.scope.account_id !== capability.lifecycle.accountId ||
    prior.scope.threshold_session_id !== capability.lifecycle.thresholdSessionId ||
    prior.scope.signer_set_id !== capability.lifecycle.signerSetId ||
    prior.scope.signing_worker_id !== capability.lifecycle.signingWorkerId ||
    prior.stateEpoch !== BigInt(capability.stateEpoch)
  ) {
    throw new Error('Email OTP Ed25519 Yao recovery bootstrap changed the active capability');
  }
}

function recoveryAdmissionRequest(
  input: VerifiedEmailOtpEd25519YaoRecoveryWorkerInputV1,
): RouterAbEd25519YaoRecoveryAdmissionRequestV1 {
  const capability = input.bootstrap.capability;
  const replacementCapabilityBinding = new Uint8Array(32);
  globalThis.crypto.getRandomValues(replacementCapabilityBinding);
  const lifecycleId = secureRandomId(
    'email-otp-ed25519-yao-recovery',
    32,
    'Email OTP Ed25519 Yao recovery lifecycle IDs',
  );
  const replacementActivationId = parseMpcMaterialActivationId(
    secureRandomId(
      'email-otp-ed25519-yao-recovery-material-activation',
      32,
      'Email OTP Ed25519 Yao recovery material activation IDs',
    ),
  );
  const replacementLifecycleBinding = parseMpcLifecycleBindingRef(
    `${lifecycleId}:material-activation`,
  );
  if (!replacementActivationId.ok || !replacementLifecycleBinding.ok) {
    throw new Error('Email OTP Ed25519 Yao recovery material activation identity is invalid');
  }
  const replacementMaterialActivation = buildMpcMaterialActivationRef({
    activationId: replacementActivationId.value,
    capability: capability.materialActivation.capability,
    materialOwner: capability.materialActivation.materialOwner,
    keyBinding: capability.materialActivation.keyBinding,
    lifecycleBinding: replacementLifecycleBinding.value,
    signingWorker: capability.materialActivation.signingWorker,
  });
  try {
    const parsed = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1({
      scope: {
        lifecycle_id: lifecycleId,
        root_share_epoch: capability.lifecycle.rootShareEpoch,
        account_id: capability.lifecycle.accountId,
        threshold_session_id: input.bootstrap.session.thresholdSessionId,
        signer_set_id: capability.lifecycle.signerSetId,
        signing_worker_id: capability.lifecycle.signingWorkerId,
        material_activation: {
          kind: replacementMaterialActivation.kind,
          activation_id: replacementMaterialActivation.activationId,
          capability: replacementMaterialActivation.capability,
          material_owner: replacementMaterialActivation.materialOwner,
          key_binding: replacementMaterialActivation.keyBinding,
          lifecycle_binding: replacementMaterialActivation.lifecycleBinding,
          signing_worker: replacementMaterialActivation.signingWorker,
        },
      },
      active_material_activation: {
        kind: capability.materialActivation.kind,
        activation_id: capability.materialActivation.activationId,
        capability: capability.materialActivation.capability,
        material_owner: capability.materialActivation.materialOwner,
        key_binding: capability.materialActivation.keyBinding,
        lifecycle_binding: capability.materialActivation.lifecycleBinding,
        signing_worker: capability.materialActivation.signingWorker,
      },
      application_binding: capability.applicationBinding,
      participant_ids: capability.participantIds,
      active_capability_binding: capability.activeCapabilityBinding,
      replacement_capability_binding: [...replacementCapabilityBinding],
      registered_public_key: capability.registeredPublicKey,
    });
    if (!parsed.ok) throw new Error(parsed.message);
    return parsed.value;
  } finally {
    replacementCapabilityBinding.fill(0);
  }
}

function assertRecoveredMetadataContinuity(args: {
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
  prior: EmailOtpEd25519YaoRecoveryContinuityMetadataV1;
  recovered: RouterAbEd25519YaoActiveClientMetadataV1;
  activation: RouterAbEd25519YaoRecoveryActivationReceiptV1;
}): void {
  const expectedEpoch = args.prior.stateEpoch + 1n;
  if (
    args.recovered.kind !== args.prior.kind ||
    args.recovered.scope.lifecycle_id !== args.request.scope.lifecycle_id ||
    args.recovered.scope.root_share_epoch !== args.request.scope.root_share_epoch ||
    args.recovered.scope.account_id !== args.request.scope.account_id ||
    args.recovered.scope.threshold_session_id !== args.request.scope.threshold_session_id ||
    args.recovered.scope.signer_set_id !== args.request.scope.signer_set_id ||
    args.recovered.scope.signing_worker_id !== args.request.scope.signing_worker_id ||
    args.recovered.applicationBinding.wallet_id !== args.prior.applicationBinding.wallet_id ||
    args.recovered.applicationBinding.near_ed25519_signing_key_id !==
      args.prior.applicationBinding.near_ed25519_signing_key_id ||
    args.recovered.applicationBinding.signing_root_id !==
      args.prior.applicationBinding.signing_root_id ||
    args.recovered.applicationBinding.key_creation_signer_slot !==
      args.prior.applicationBinding.key_creation_signer_slot ||
    !equalParticipants(args.recovered.participantIds, args.prior.participantIds) ||
    !equalBytes(args.recovered.registeredPublicKey, args.prior.registeredPublicKey) ||
    args.recovered.stateEpoch !== expectedEpoch ||
    BigInt(args.activation.public_receipt.state_epoch) !== expectedEpoch ||
    !equalBytes(
      args.activation.active_capability_binding,
      args.request.replacement_capability_binding,
    ) ||
    !equalBytes(
      args.activation.retired_capability_binding,
      args.request.active_capability_binding,
    ) ||
    !equalBytes(
      args.activation.public_receipt.registered_public_key,
      args.prior.registeredPublicKey,
    )
  ) {
    throw new Error('Email OTP Ed25519 Yao recovery changed the registered capability identity');
  }
}

function requireActiveHandle(lifecycle: WorkerActiveClientLifecycle): string {
  switch (lifecycle.kind) {
    case 'active':
      return lifecycle.activeClientHandle;
    case 'disposed':
      throw new Error('Email OTP Ed25519 Yao worker Client is disposed');
    default:
      return assertNever(lifecycle);
  }
}

function sendActiveClientDisposal(args: {
  workerContext: WorkerOperationContext;
  activeClientHandle: string;
}): void {
  void args.workerContext
    .requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'disposeEmailOtpEd25519YaoActiveClient',
        payload: { activeClientHandle: args.activeClientHandle },
      },
    })
    .catch(() => undefined);
}

export async function disposeEmailOtpEd25519YaoActiveClientV1(args: {
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

export class EmailOtpEd25519YaoWorkerActiveClientV1 implements RouterAbEd25519YaoActiveClientV1 {
  private lifecycle: WorkerActiveClientLifecycle;
  private readonly activeMetadata: RouterAbEd25519YaoActiveClientMetadataV1;

  constructor(
    private readonly workerContext: WorkerOperationContext,
    activeClientHandle: string,
    metadata: RouterAbEd25519YaoActiveClientMetadataV1,
  ) {
    this.lifecycle = {
      kind: 'active',
      activeClientHandle: requireNonEmpty(activeClientHandle, 'activeClientHandle'),
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
        payload: {
          activeClientHandle: requireActiveHandle(this.lifecycle),
          input,
        },
      },
    });
  }

  metadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
    return cloneMetadata(this.activeMetadata);
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
        const activeClientHandle = this.lifecycle.activeClientHandle;
        this.lifecycle = { kind: 'disposed' };
        sendActiveClientDisposal({ workerContext: this.workerContext, activeClientHandle });
        return;
      }
      case 'disposed':
        return;
      default:
        return assertNever(this.lifecycle);
    }
  }
}

export type RehydrateEmailOtpEd25519YaoOperationMaterialInputV1 = {
  workerContext: WorkerOperationContext;
  relayUrl: string;
  walletId: string;
  nearAccountId: string;
  signerSlot: number;
  providerSubjectId: string;
  expectedOperationalPublicKey: string;
  expectedThresholdSessionId: ThresholdEd25519SessionId;
  expectedMaterialActivation: MpcMaterialActivationRef;
  normalSigningRequest: RouterAbNormalSigningPrepareRequestV2Wire;
  displayDigest: string;
  proof: EmailOtpEd25519YaoOperationStepUpProofV1;
};

export type RehydrateEmailOtpEd25519YaoOperationMaterialResultV1 = {
  activeClient: EmailOtpEd25519YaoWorkerActiveClientV1;
  issuedAuthorization: EmailOtpEd25519YaoIssuedOperationAuthorizationV1;
};

export async function rehydrateEmailOtpEd25519YaoOperationMaterialV1(
  input: RehydrateEmailOtpEd25519YaoOperationMaterialInputV1,
): Promise<RehydrateEmailOtpEd25519YaoOperationMaterialResultV1> {
  if (input.proof.providerSubjectId !== input.providerSubjectId) {
    throw new Error('Email OTP Ed25519 operation proof changed provider identity');
  }
  const result = await requestRehydrateEmailOtpEd25519YaoOperationMaterial(input);
  const activation = nearEd25519YaoMaterialActivationFromMetadata(result.metadata);
  if (
    result.metadata.scope.threshold_session_id !== input.expectedThresholdSessionId ||
    result.metadata.applicationBinding.wallet_id !== input.walletId ||
    result.metadata.applicationBinding.key_creation_signer_slot !== input.signerSlot ||
    `ed25519:${base58Encode(result.metadata.registeredPublicKey)}` !==
      input.expectedOperationalPublicKey ||
    !mpcMaterialActivationRefsEqual(activation, input.expectedMaterialActivation)
  ) {
    await disposeEmailOtpEd25519YaoActiveClientV1({
      workerContext: input.workerContext,
      activeClientHandle: result.activeClientHandle,
    }).catch(() => undefined);
    throw new Error('Email OTP Ed25519 worker activated different signing material');
  }
  return {
    activeClient: new EmailOtpEd25519YaoWorkerActiveClientV1(
      input.workerContext,
      result.activeClientHandle,
      result.metadata,
    ),
    issuedAuthorization: result.issuedAuthorization,
  };
}

class EmailOtpEd25519YaoWorkerPendingRegistrationV1 implements ProductEd25519YaoPendingRegistrationPortV1 {
  private lifecycle: WorkerPendingRegistrationLifecycle;

  constructor(
    private readonly workerContext: WorkerOperationContext,
    pendingHandle: string,
    private readonly operationalPublicKey: string,
    private readonly reference: ProductEd25519YaoActivationReferenceV1,
  ) {
    this.lifecycle = {
      kind: 'pending',
      pendingHandle: requireNonEmpty(pendingHandle, 'pendingHandle'),
    };
  }

  publicKey(): string {
    switch (this.lifecycle.kind) {
      case 'pending':
      case 'persisting_material':
      case 'material_persisted':
        return this.operationalPublicKey;
      case 'disposed':
        throw new Error('Email OTP Ed25519 Yao registration is disposed');
      default:
        return assertNever(this.lifecycle);
    }
  }

  activationReference(): ProductEd25519YaoActivationReferenceV1 {
    switch (this.lifecycle.kind) {
      case 'pending':
        return {
          kind: this.reference.kind,
          lifecycle_id: this.reference.lifecycle_id,
          session_id: [...this.reference.session_id],
        };
      case 'persisting_material':
      case 'material_persisted':
        throw new Error('Email OTP Ed25519 Yao registration material is already persisted');
      case 'disposed':
        throw new Error('Email OTP Ed25519 Yao registration is disposed');
      default:
        return assertNever(this.lifecycle);
    }
  }

  async persistRegistrationMaterial(
    args: ProductEd25519YaoRegistrationMaterialPersistenceV1,
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    switch (this.lifecycle.kind) {
      case 'pending': {
        if (args.kind !== 'worker_owned') {
          throw new Error('Email OTP Ed25519 registration material must remain worker-owned');
        }
        const result = this.persistPendingRegistrationMaterial({
          pendingHandle: this.lifecycle.pendingHandle,
          walletId: args.walletId,
          nearAccountId: args.nearAccountId,
          nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
          signerSlot: args.signerSlot,
          signingRootVersion: args.signingRootVersion,
          expectedOperationalPublicKey: args.expectedOperationalPublicKey,
        });
        this.lifecycle = { kind: 'persisting_material', result };
        const metadata = await result;
        this.lifecycle = { kind: 'material_persisted', metadata };
        return metadata;
      }
      case 'persisting_material':
        return await this.lifecycle.result;
      case 'material_persisted':
        return this.lifecycle.metadata;
      case 'disposed':
        throw new Error('Email OTP Ed25519 Yao registration is disposed');
      default:
        return assertNever(this.lifecycle);
    }
  }

  async dispose(): Promise<void> {
    switch (this.lifecycle.kind) {
      case 'pending': {
        const pendingHandle = this.lifecycle.pendingHandle;
        this.lifecycle = { kind: 'disposed' };
        await this.workerContext.requestWorkerOperation({
          kind: 'emailOtp',
          request: {
            type: 'disposeEmailOtpEd25519YaoRegistration',
            payload: { pendingHandle },
          },
        });
        return;
      }
      case 'persisting_material':
        await this.lifecycle.result;
        return;
      case 'material_persisted':
      case 'disposed':
        return;
      default:
        return assertNever(this.lifecycle);
    }
  }

  private async persistPendingRegistrationMaterial(args: {
    pendingHandle: string;
    walletId: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    signerSlot: number;
    signingRootVersion: string;
    expectedOperationalPublicKey: string;
  }): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    try {
      const result = await this.workerContext.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'persistEmailOtpEd25519YaoRegistrationMaterial',
          payload: args,
        },
      });
      if (
        `ed25519:${base58Encode(result.metadata.registeredPublicKey)}` !==
          args.expectedOperationalPublicKey ||
        result.metadata.applicationBinding.wallet_id !== args.walletId ||
        result.metadata.applicationBinding.near_ed25519_signing_key_id !==
          args.nearEd25519SigningKeyId ||
        result.metadata.applicationBinding.key_creation_signer_slot !== args.signerSlot ||
        result.metadata.scope.root_share_epoch !== args.signingRootVersion
      ) {
        throw new Error('Email OTP Ed25519 worker persisted a different signer material identity');
      }
      return result.metadata;
    } catch (error: unknown) {
      this.lifecycle = { kind: 'disposed' };
      throw error;
    }
  }
}

function registrationRootScope(args: {
  providerSubject: string;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}): EmailOtpEd25519YaoRootScope {
  return emailOtpEd25519YaoRegistrationRootScopeV1(args);
}

async function disposeWorkerFactorOwnership(args: {
  workerContext: WorkerOperationContext;
  ownership: WorkerFactorOwnership;
}): Promise<void> {
  switch (args.ownership.kind) {
    case 'pending_factor': {
      await disposeEmailOtpEd25519YaoPendingFactorV1({
        workerContext: args.workerContext,
        pendingFactorHandle: args.ownership.pendingFactorHandle,
      });
      return;
    }
    case 'bound_root': {
      await disposeEmailOtpEd25519YaoRootV1({
        workerContext: args.workerContext,
        rootHandle: args.ownership.rootHandle,
      });
      return;
    }
    case 'pending_registration':
      await args.workerContext.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'disposeEmailOtpEd25519YaoRegistration',
          payload: { pendingHandle: args.ownership.pendingRegistrationHandle },
        },
      });
      return;
    case 'consumed':
      return;
    default:
      return assertNever(args.ownership);
  }
}

export async function startEmailOtpEd25519YaoWorkerRegistrationV1(
  input: VerifiedEmailOtpEd25519YaoRegistrationWorkerInputV1,
): Promise<ProductEd25519YaoPendingRegistrationPortV1> {
  let ownership: WorkerFactorOwnership = {
    kind: 'pending_factor',
    pendingFactorHandle: input.pendingFactorHandle,
  };
  try {
    const scope = registrationRootScope({
      providerSubject: input.providerSubject,
      admissionRequest: input.admissionRequest,
    });
    if (scope.walletId !== input.walletId) {
      throw new Error('Email OTP Ed25519 Yao admission changed the verified wallet');
    }
    const bearerToken = requireNonEmpty(
      input.registrationBearerToken,
      'registrationBearerToken',
    );
    const routerOrigin = new URL(input.routerOrigin).origin;
    const bound = await input.workerContext.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'bindEmailOtpEd25519YaoRoot',
        payload: {
          pendingFactorHandle: input.pendingFactorHandle,
          scope,
        },
      },
    });
    ownership = { kind: 'bound_root', rootHandle: bound.rootHandle };
    const started = await input.workerContext.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'startEmailOtpEd25519YaoRegistration',
        payload: {
          rootHandle: bound.rootHandle,
          admissionRequest: input.admissionRequest,
          admissionReceipt: input.admissionReceipt,
          walletId: input.walletId,
          providerSubject: input.providerSubject,
          registrationAuthorityId: input.registrationAuthorityId,
          bearerToken,
          routerOrigin,
        },
      },
    });
    ownership = {
      kind: 'pending_registration',
      pendingRegistrationHandle: started.pendingHandle,
    };
    if (input.onYaoDiagnostics && (started.routerServerTiming || started.clientTimings)) {
      try {
        input.onYaoDiagnostics({
          ...(started.routerServerTiming ? { routerServerTiming: started.routerServerTiming } : {}),
          ...(started.clientTimings ? { clientTimings: started.clientTimings } : {}),
        });
      } catch {
        // Diagnostics must never change registration behavior.
      }
    }
    const pending = new EmailOtpEd25519YaoWorkerPendingRegistrationV1(
      input.workerContext,
      started.pendingHandle,
      started.operationalPublicKey,
      {
        kind: started.activationReference.kind,
        lifecycle_id: started.activationReference.lifecycle_id,
        session_id: [...started.activationReference.session_id],
      },
    );
    ownership = { kind: 'consumed' };
    return pending;
  } catch (error) {
    try {
      await disposeWorkerFactorOwnership({ workerContext: input.workerContext, ownership });
    } catch {}
    throw error;
  }
}

export async function recoverEmailOtpEd25519YaoWorkerClientV1(
  input: VerifiedEmailOtpEd25519YaoRecoveryWorkerInputV1,
): Promise<EmailOtpEd25519YaoWorkerRecoveryResultV1> {
  let ownership: WorkerFactorOwnership = {
    kind: 'pending_factor',
    pendingFactorHandle: input.pendingFactorHandle,
  };
  try {
    assertPriorRecoveryContinuity(input);
    const request = recoveryAdmissionRequest(input);
    const scope = emailOtpEd25519YaoRecoveryRootScopeV1({
      providerSubject: input.providerSubject,
      admissionRequest: request,
    });
    const walletId = String(input.bootstrap.session.walletId);
    if (scope.walletId !== walletId) {
      throw new Error('Email OTP Ed25519 Yao recovery changed the verified wallet');
    }
    const bearerToken = requireNonEmpty(
      input.bootstrap.session.walletSessionJwt,
      'bootstrap.session.walletSessionJwt',
    );
    const routerOrigin = new URL(input.routerOrigin).origin;
    const bound = await input.workerContext.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'bindEmailOtpEd25519YaoRoot',
        payload: {
          pendingFactorHandle: input.pendingFactorHandle,
          scope,
        },
      },
    });
    ownership = { kind: 'bound_root', rootHandle: bound.rootHandle };
    const recovered = await input.workerContext.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'recoverEmailOtpEd25519Yao',
        payload: {
          rootHandle: bound.rootHandle,
          admissionRequest: request,
          walletId,
          nearAccountId: input.bootstrap.session.nearAccountId,
          signingRootVersion: input.bootstrap.session.signingRootVersion,
          providerSubject: input.providerSubject,
          registrationAuthorityId: input.registrationAuthorityId,
          bearerToken,
          routerOrigin,
          sessionPolicy: {
            thresholdSessionId: input.bootstrap.session.thresholdSessionId,
            expiresAtMs: input.bootstrap.session.expiresAtMs,
            remainingUses: input.bootstrap.session.remainingUses,
          },
        },
      },
    });
    ownership = { kind: 'consumed' };
    const activeClient = new EmailOtpEd25519YaoWorkerActiveClientV1(
      input.workerContext,
      recovered.activeClientHandle,
      recovered.metadata,
    );
    try {
      assertRecoveredMetadataContinuity({
        request,
        prior: input.expectedPriorMetadata,
        recovered: recovered.metadata,
        activation: recovered.activation,
      });
      return { activeClient, activation: recovered.activation };
    } catch (error) {
      activeClient.dispose();
      throw error;
    }
  } catch (error) {
    try {
      await disposeWorkerFactorOwnership({ workerContext: input.workerContext, ownership });
    } catch {}
    throw error;
  }
}

export async function disposeEmailOtpEd25519YaoPendingFactorV1(args: {
  workerContext: WorkerOperationContext;
  pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
}): Promise<boolean> {
  const result = await args.workerContext.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'disposeEmailOtpEd25519YaoPendingFactor',
      payload: { pendingFactorHandle: args.pendingFactorHandle },
    },
  });
  return result.removed;
}

export async function disposeEmailOtpEd25519YaoRootV1(args: {
  workerContext: WorkerOperationContext;
  rootHandle: EmailOtpEd25519YaoRootHandle;
}): Promise<boolean> {
  const result = await args.workerContext.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'disposeEmailOtpEd25519YaoRoot',
      payload: { rootHandle: args.rootHandle },
    },
  });
  return result.removed;
}
