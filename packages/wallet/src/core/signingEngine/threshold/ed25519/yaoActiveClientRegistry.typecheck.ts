import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519YaoOperationMaterial } from '@/core/signingEngine/interfaces/near';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  Ed25519YaoActiveClientRegistry,
  type Ed25519YaoActiveClientIdentityV1,
} from './yaoActiveClientRegistry';

declare const walletId: WalletId;
declare const nearAccountId: AccountId;
declare const material: NearEd25519YaoOperationMaterial;
declare const materialActivation: MpcMaterialActivationRef;

const validIdentity = {
  walletId,
  nearAccountId,
  materialActivation,
} satisfies Ed25519YaoActiveClientIdentityV1;

const registry = new Ed25519YaoActiveClientRegistry();
void registry.activate(material);
void registry.resolve(validIdentity);
void registry.disposeWallet(walletId);

// @ts-expect-error Active Client lookup requires the wallet identity.
registry.resolve({ nearAccountId, materialActivation });

// @ts-expect-error Active Client lookup requires the NEAR account identity.
registry.resolve({ walletId, materialActivation });
