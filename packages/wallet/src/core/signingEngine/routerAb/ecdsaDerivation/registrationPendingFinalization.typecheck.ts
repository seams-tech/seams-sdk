import type {
  RouterAbEcdsaRegistrationRequestFactsV1,
  RouterAbEcdsaRegistrationRequestV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1,
  decodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  encodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  type RouterAbEcdsaRegistrationPendingFinalizationV1,
} from './registrationPendingFinalization';

declare const registrationFacts: RouterAbEcdsaRegistrationRequestFactsV1;
declare const registrationRequest: RouterAbEcdsaRegistrationRequestV1;
declare const clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
declare const runtimePolicyScope: RuntimePolicyScope;

const valid = buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1({
  runtimePolicyScope,
  registrationFacts,
  registrationRequest,
  clientActivation,
});
const encoded: string = encodeRouterAbEcdsaRegistrationPendingFinalizationV1(valid);
const decoded: RouterAbEcdsaRegistrationPendingFinalizationV1 =
  decodeRouterAbEcdsaRegistrationPendingFinalizationV1(encoded);
void decoded;

buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1({
  runtimePolicyScope,
  registrationFacts,
  registrationRequest,
  clientActivation,
  // @ts-expect-error legacy ceremony aliases are outside the exact payload.
  registrationCeremonyId: 'legacy-ceremony-alias',
});

buildWalletCustodyRouterAbEcdsaRegistrationPendingFinalizationV1({
  runtimePolicyScope,
  registrationFacts,
  registrationRequest,
  clientActivation,
  // @ts-expect-error callers cannot provide the payload discriminant.
  kind: 'router_ab_ecdsa_registration_pending_finalization_v1',
});
