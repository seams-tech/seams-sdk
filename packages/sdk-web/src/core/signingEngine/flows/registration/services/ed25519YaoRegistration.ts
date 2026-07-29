import { base58Encode } from '@shared/utils/base58';
import {
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoLifecycleScopeV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoBytes32V1,
} from '@shared/utils/routerAbEd25519Yao';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import { type Ed25519YaoActiveClientIdentityV1 } from '@/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  RouterAbEd25519YaoClientV1,
  type RouterAbEd25519YaoActiveClientV1,
  type RouterAbEd25519YaoSealableActiveClientV1,
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
  | {
      ok: true;
      registration: ProductEd25519YaoPendingRegistrationPortV1;
      /**
       * Raw Router `Server-Timing` for the Yao execute call, when the Router
       * exposed it. Diagnostics only — never read for lifecycle decisions.
       */
      routerServerTiming?: string;
      /** Client-observed Yao sub-steps in ms. Diagnostics only. */
      clientTimings?: { admissionMs: number; sessionCreateMs: number };
    }
  | ProductEd25519YaoRegistrationFailureV1;

export type ProductEd25519YaoActivationReferenceV1 = {
  kind: 'router_ab_ed25519_yao_activation_reference_v1';
  lifecycle_id: string;
  session_id: RouterAbEd25519YaoBytes32V1;
};

export type ProductEd25519YaoBrowserMaterialPersistencePortV1 = {
  persist(
    activeClient: RouterAbEd25519YaoSealableActiveClientV1,
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1>;
};

export type ProductEd25519YaoRegistrationMaterialPersistenceV1 =
  | {
      kind: 'browser_owned';
      persistence: ProductEd25519YaoBrowserMaterialPersistencePortV1;
      walletId?: never;
      nearAccountId?: never;
      nearEd25519SigningKeyId?: never;
      signerSlot?: never;
      signingRootVersion?: never;
      expectedOperationalPublicKey?: never;
    }
  | {
      kind: 'worker_owned';
      persistence?: never;
      walletId: string;
      nearAccountId: string;
      nearEd25519SigningKeyId: string;
      signerSlot: number;
      signingRootVersion: string;
      expectedOperationalPublicKey: string;
    };

export interface ProductEd25519YaoPendingRegistrationPortV1 {
  publicKey(): string;
  activationReference(): ProductEd25519YaoActivationReferenceV1;
  persistRegistrationMaterial(
    args: ProductEd25519YaoRegistrationMaterialPersistenceV1,
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1>;
  dispose(): Promise<void>;
}

type PendingRegistrationLifecycleV1 =
  | {
      kind: 'active_uncommitted';
      activeClient: RouterAbEd25519YaoSealableActiveClientV1;
      operationalPublicKey: string;
    }
  | {
      kind: 'persisting_material';
      result: Promise<RouterAbEd25519YaoActiveClientMetadataV1>;
      operationalPublicKey: string;
      activeClient?: never;
    }
  | {
      kind: 'material_persisted';
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      operationalPublicKey: string;
      activeClient?: never;
      result?: never;
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
    case 'persisting_material':
    case 'material_persisted':
      throw new Error('Product Ed25519 Yao registration material is already persisted');
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

export class PendingProductEd25519YaoRegistrationV1 implements ProductEd25519YaoPendingRegistrationPortV1 {
  private lifecycle: PendingRegistrationLifecycleV1;

  private constructor(activeClient: RouterAbEd25519YaoSealableActiveClientV1) {
    this.lifecycle = {
      kind: 'active_uncommitted',
      activeClient,
      operationalPublicKey: operationalPublicKey(activeClient),
    };
  }

  static fromVerifiedClient(
    activeClient: RouterAbEd25519YaoSealableActiveClientV1,
  ): PendingProductEd25519YaoRegistrationV1 {
    if (activeClient.status().kind !== 'active') {
      throw new Error('Product Ed25519 Yao registration requires active verified Client state');
    }
    return new PendingProductEd25519YaoRegistrationV1(activeClient);
  }

  publicKey(): string {
    switch (this.lifecycle.kind) {
      case 'active_uncommitted':
      case 'persisting_material':
      case 'material_persisted':
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

  async persistRegistrationMaterial(
    args: ProductEd25519YaoRegistrationMaterialPersistenceV1,
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    switch (this.lifecycle.kind) {
      case 'active_uncommitted': {
        if (args.kind !== 'browser_owned') {
          throw new Error('Passkey Ed25519 registration material must remain browser-owned');
        }
        const current = this.lifecycle;
        try {
          const result = args.persistence.persist(current.activeClient);
          this.lifecycle = {
            kind: 'persisting_material',
            result,
            operationalPublicKey: current.operationalPublicKey,
          };
          const metadata = await result;
          current.activeClient.dispose();
          this.lifecycle = {
            kind: 'material_persisted',
            metadata,
            operationalPublicKey: current.operationalPublicKey,
          };
          return metadata;
        } catch (error) {
          current.activeClient.dispose();
          this.lifecycle = { kind: 'disposed' };
          throw error;
        }
      }
      case 'persisting_material':
        return await this.lifecycle.result;
      case 'material_persisted':
        return this.lifecycle.metadata;
      case 'disposed':
        throw new Error('Product Ed25519 Yao registration is disposed');
      default:
        return assertNeverLifecycle(this.lifecycle);
    }
  }

  async dispose(): Promise<void> {
    switch (this.lifecycle.kind) {
      case 'active_uncommitted':
        this.lifecycle.activeClient.dispose();
        this.lifecycle = { kind: 'disposed' };
        return;
      case 'persisting_material':
        await this.lifecycle.result;
        return;
      case 'material_persisted':
      case 'disposed':
        return;
      default:
        return assertNeverLifecycle(this.lifecycle);
    }
  }
}

export async function registerProductEd25519YaoV1(
  args: {
    request: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
    factor: RouterAbEd25519YaoClientRootFactorV1;
    transport: RouterAbEd25519YaoRegistrationTransportV1;
  } & (
    | {
        admission: {
          kind: 'verified_receipt';
          receipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
        };
      }
    | {
        admission: { kind: 'transport_request' };
      }
  ),
): Promise<ProductEd25519YaoRegistrationResultV1> {
  const client = await RouterAbEd25519YaoClientV1.initializeBundled();
  const result =
    args.admission.kind === 'verified_receipt'
      ? await client.registerAdmitted({
          request: args.request,
          admissionReceipt: args.admission.receipt,
          factor: args.factor,
          transport: args.transport,
        })
      : await client.register({
          request: args.request,
          factor: args.factor,
          transport: args.transport,
        });
  if (!result.ok) return result;
  try {
    return {
      ok: true,
      registration: PendingProductEd25519YaoRegistrationV1.fromVerifiedClient(result.activeClient),
      ...(result.routerServerTiming ? { routerServerTiming: result.routerServerTiming } : {}),
      ...(result.clientTimings ? { clientTimings: result.clientTimings } : {}),
    };
  } catch (error) {
    result.activeClient.dispose();
    throw error;
  }
}
