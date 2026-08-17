import type { RouterAbEcdsaOperationStepUpPreparationV1Wire } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { HydratedEcdsaSignerMaterial } from '../../../session/identity/evmFamilyEcdsaIdentity';
import type {
  BuildReadySecp256k1SigningMaterialInput,
  ReusableEcdsaSigningAuthorization,
} from './secp256k1';

declare const signerSession: HydratedEcdsaSignerMaterial;
declare const reusableAuthorization: ReusableEcdsaSigningAuthorization;
declare const operationAuthorization: Extract<
  RouterAbNormalSigningAuthorizationWire,
  { readonly kind: 'operation_step_up' }
>;
declare const operationPreparation: RouterAbEcdsaOperationStepUpPreparationV1Wire;

const base = {
  walletId: 'wallet-fixture',
  signerSession,
  expiresAtMs: 1_900_000_000_000,
  singleUseEmailOtpSession: false,
} as const;

const reusable: BuildReadySecp256k1SigningMaterialInput = {
  ...base,
  authorization: reusableAuthorization,
  credential: {
    kind: 'reusable_wallet_session',
    walletSessionToken: 'wallet-session-token',
  },
};

const operation: BuildReadySecp256k1SigningMaterialInput = {
  ...base,
  authorization: operationAuthorization,
  credential: { kind: 'operation_step_up', walletSessionToken: 'opaque-token' },
  operationStepUpPreparation: operationPreparation,
};

const operationWithWalletCredential: BuildReadySecp256k1SigningMaterialInput = {
  ...base,
  authorization: operationAuthorization,
  // @ts-expect-error Operation step-up credentials require the opaque owner bearer.
  credential: {
    kind: 'operation_step_up',
  },
  operationStepUpPreparation: operationPreparation,
};

void reusable;
void operation;
void operationWithWalletCredential;
