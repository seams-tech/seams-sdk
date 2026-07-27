import type { EcdsaRoleLocalPendingStateBlob } from '@/core/platform/types';
import type {
  RouterAbEcdsaRegistrationRequestFactsV1,
  RouterAbEcdsaRegistrationRequestV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildRouterAbEcdsaRegistrationPendingFinalizationV1,
  decodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  encodeRouterAbEcdsaRegistrationPendingFinalizationV1,
  type RouterAbEcdsaRegistrationPendingFinalizationV1,
} from './registrationPendingFinalization';

declare const pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
declare const registrationFacts: RouterAbEcdsaRegistrationRequestFactsV1;
declare const registrationRequest: RouterAbEcdsaRegistrationRequestV1;
declare const clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;

const valid = buildRouterAbEcdsaRegistrationPendingFinalizationV1({
  pendingStateBlob,
  registrationFacts,
  registrationRequest,
  clientActivation,
});
const encoded: string = encodeRouterAbEcdsaRegistrationPendingFinalizationV1(valid);
const decoded: RouterAbEcdsaRegistrationPendingFinalizationV1 =
  decodeRouterAbEcdsaRegistrationPendingFinalizationV1(encoded);
void decoded;

// @ts-expect-error pending finalization requires the worker-owned pending state.
buildRouterAbEcdsaRegistrationPendingFinalizationV1({
  registrationFacts,
  registrationRequest,
  clientActivation,
});

buildRouterAbEcdsaRegistrationPendingFinalizationV1({
  pendingStateBlob,
  registrationFacts,
  registrationRequest,
  clientActivation,
  // @ts-expect-error legacy ceremony aliases are outside the exact payload.
  registrationCeremonyId: 'legacy-ceremony-alias',
});

buildRouterAbEcdsaRegistrationPendingFinalizationV1({
  pendingStateBlob,
  registrationFacts,
  registrationRequest,
  clientActivation,
  // @ts-expect-error callers cannot provide the payload discriminant.
  kind: 'router_ab_ecdsa_registration_pending_finalization_v1',
});
