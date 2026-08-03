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
    kind: 'reusable_wallet_session_jwt',
    walletSessionJwt: 'wallet-session-jwt',
  },
};

const operation: BuildReadySecp256k1SigningMaterialInput = {
  ...base,
  authorization: operationAuthorization,
  credential: { kind: 'app_session_jwt', appSessionJwt: 'app-session-jwt' },
  operationStepUpPreparation: operationPreparation,
};

// @ts-expect-error Reusable authorization cannot carry app-session authority.
const reusableWithAppCredential: BuildReadySecp256k1SigningMaterialInput = {
  ...base,
  authorization: reusableAuthorization,
  credential: { kind: 'app_session_jwt', appSessionJwt: 'app-session-jwt' },
};

// @ts-expect-error Operation step-up cannot carry a reusable Wallet Session JWT.
const operationWithWalletCredential: BuildReadySecp256k1SigningMaterialInput = {
  ...base,
  authorization: operationAuthorization,
  credential: {
    kind: 'reusable_wallet_session_jwt',
    walletSessionJwt: 'wallet-session-jwt',
  },
  operationStepUpPreparation: operationPreparation,
};

void reusable;
void operation;
void reusableWithAppCredential;
void operationWithWalletCredential;
