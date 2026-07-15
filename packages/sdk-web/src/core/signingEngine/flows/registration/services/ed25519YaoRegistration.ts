import { base58Encode } from '@shared/utils/base58';
import {
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoLifecycleScopeV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoBytes32V1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  NearEd25519YaoSigningCapability,
  NearResolvedEd25519SigningSessionState,
} from '@/core/signingEngine/interfaces/near';
import { type Ed25519YaoActiveClientIdentityV1 } from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import {
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoClientRootFactorV1,
  type RouterAbEd25519YaoRegistrationFailureV1,
  type RouterAbEd25519YaoRegistrationTransportV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';

export type ProductEd25519YaoRegistrationRequestInputV1 = {
  scope: RouterAbEd25519YaoLifecycleScopeV1;
  applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  participantIds: readonly [number, number];
};

export type ProductEd25519YaoRegistrationFailureV1 = RouterAbEd25519YaoRegistrationFailureV1;

export type ProductEd25519YaoCapabilityActivationPortV1 = {
  activateVerifiedNearEd25519YaoSigningCapability(
    capability: NearEd25519YaoSigningCapability,
  ): Promise<Ed25519YaoActiveClientIdentityV1>;
};

export type ProductEd25519YaoRegistrationResultV1 =
  | { ok: true; registration: ProductEd25519YaoPendingRegistrationPortV1 }
  | ProductEd25519YaoRegistrationFailureV1;

export type ProductEd25519YaoActivationReferenceV1 = {
  kind: 'router_ab_ed25519_yao_activation_reference_v1';
  lifecycle_id: string;
  session_id: RouterAbEd25519YaoBytes32V1;
};

export interface ProductEd25519YaoPendingRegistrationPortV1 {
  publicKey(): string;
  activationReference(): ProductEd25519YaoActivationReferenceV1;
  commit(args: {
    activation: ProductEd25519YaoCapabilityActivationPortV1;
    walletSessionState: NearResolvedEd25519SigningSessionState;
  }): Promise<Ed25519YaoActiveClientIdentityV1>;
  dispose(): Promise<void>;
}

type PendingRegistrationLifecycleV1 =
  | {
      kind: 'active_uncommitted';
      activeClient: RouterAbEd25519YaoActiveClientV1;
      operationalPublicKey: string;
    }
  | {
      kind: 'committed';
      identity: Ed25519YaoActiveClientIdentityV1;
      operationalPublicKey: string;
      activeClient?: never;
    }
  | {
      kind: 'disposed';
      activeClient?: never;
      identity?: never;
      operationalPublicKey?: never;
    };

function assertNeverLifecycle(value: never): never {
  throw new Error(`Unexpected product Ed25519 Yao registration state: ${String(value)}`);
}

function requireActiveClient(
  lifecycle: PendingRegistrationLifecycleV1,
): Extract<PendingRegistrationLifecycleV1, { kind: 'active_uncommitted' }> {
  switch (lifecycle.kind) {
    case 'active_uncommitted':
      return lifecycle;
    case 'committed':
      throw new Error('Product Ed25519 Yao registration is already committed');
    case 'disposed':
      throw new Error('Product Ed25519 Yao registration is disposed');
    default:
      return assertNeverLifecycle(lifecycle);
  }
}

function operationalPublicKey(activeClient: RouterAbEd25519YaoActiveClientV1): string {
  return `ed25519:${base58Encode(activeClient.metadata().registeredPublicKey)}`;
}

export function buildProductEd25519YaoRegistrationRequestV1(
  input: ProductEd25519YaoRegistrationRequestInputV1,
): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  const parsed = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: input.scope,
    application_binding: input.applicationBinding,
    participant_ids: input.participantIds,
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

export class PendingProductEd25519YaoRegistrationV1
  implements ProductEd25519YaoPendingRegistrationPortV1
{
  private lifecycle: PendingRegistrationLifecycleV1;

  private constructor(activeClient: RouterAbEd25519YaoActiveClientV1) {
    this.lifecycle = {
      kind: 'active_uncommitted',
      activeClient,
      operationalPublicKey: operationalPublicKey(activeClient),
    };
  }

  static fromVerifiedClient(
    activeClient: RouterAbEd25519YaoActiveClientV1,
  ): PendingProductEd25519YaoRegistrationV1 {
    if (activeClient.status().kind !== 'active') {
      throw new Error('Product Ed25519 Yao registration requires active verified Client state');
    }
    return new PendingProductEd25519YaoRegistrationV1(activeClient);
  }

  publicKey(): string {
    switch (this.lifecycle.kind) {
      case 'active_uncommitted':
      case 'committed':
        return this.lifecycle.operationalPublicKey;
      case 'disposed':
        throw new Error('Product Ed25519 Yao registration is disposed');
      default:
        return assertNeverLifecycle(this.lifecycle);
    }
  }

  activationReference(): ProductEd25519YaoActivationReferenceV1 {
    const current = requireActiveClient(this.lifecycle);
    const metadata = current.activeClient.metadata();
    return {
      kind: 'router_ab_ed25519_yao_activation_reference_v1',
      lifecycle_id: metadata.scope.lifecycle_id,
      session_id: metadata.activeCapabilityBinding,
    };
  }

  async commit(args: {
    activation: ProductEd25519YaoCapabilityActivationPortV1;
    walletSessionState: NearResolvedEd25519SigningSessionState;
  }): Promise<Ed25519YaoActiveClientIdentityV1> {
    const current = requireActiveClient(this.lifecycle);
    const capability: NearEd25519YaoSigningCapability = {
      activeClient: current.activeClient,
      walletSessionState: args.walletSessionState,
    };
    const identity = await args.activation.activateVerifiedNearEd25519YaoSigningCapability(
      capability,
    );
    this.lifecycle = {
      kind: 'committed',
      identity,
      operationalPublicKey: current.operationalPublicKey,
    };
    return identity;
  }

  async dispose(): Promise<void> {
    switch (this.lifecycle.kind) {
      case 'active_uncommitted':
        this.lifecycle.activeClient.dispose();
        this.lifecycle = { kind: 'disposed' };
        return;
      case 'committed':
      case 'disposed':
        return;
      default:
        return assertNeverLifecycle(this.lifecycle);
    }
  }
}

export async function registerProductEd25519YaoV1(args: {
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  factor: RouterAbEd25519YaoClientRootFactorV1;
  transport: RouterAbEd25519YaoRegistrationTransportV1;
}): Promise<ProductEd25519YaoRegistrationResultV1> {
  const client = await RouterAbEd25519YaoClientV1.initializeBundled();
  const result = await client.register({
    request: args.request,
    factor: args.factor,
    transport: args.transport,
  });
  if (!result.ok) return result;
  try {
    return {
      ok: true,
      registration: PendingProductEd25519YaoRegistrationV1.fromVerifiedClient(result.activeClient),
    };
  } catch (error) {
    result.activeClient.dispose();
    throw error;
  }
}
