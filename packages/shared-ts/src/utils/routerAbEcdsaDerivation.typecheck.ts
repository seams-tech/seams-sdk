import type {
  SigningGrantId,
  ThresholdEcdsaSessionId,
} from './domainIds';
import type {
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  RouterAbEcdsaPostRegistrationSessionPolicyV1,
} from './routerAbEcdsaDerivation';
import type { RuntimePolicyScope } from '../threshold/signingRootScope';

declare const signingGrantId: SigningGrantId;
declare const thresholdSessionId: ThresholdEcdsaSessionId;
declare const runtimePolicyScope: RuntimePolicyScope;
declare const activationResponse: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;

const sessionPolicy = {
  threshold_session_id: thresholdSessionId,
  signing_grant_id: signingGrantId,
  ttl_ms: 60_000,
  remaining_uses: 2,
  runtime_policy_scope: runtimePolicyScope,
} satisfies RouterAbEcdsaPostRegistrationSessionPolicyV1;
void sessionPolicy;

const invalidSessionPolicy = {
  threshold_session_id: thresholdSessionId,
  // @ts-expect-error Raw strings must be parsed before entering protocol state.
  signing_grant_id: 'grant-unparsed',
  ttl_ms: 60_000,
  remaining_uses: 2,
  runtime_policy_scope: runtimePolicyScope,
} satisfies RouterAbEcdsaPostRegistrationSessionPolicyV1;
void invalidSessionPolicy;

const responseSigningGrantId: SigningGrantId =
  activationResponse.session.signing_grant_id;
void responseSigningGrantId;

const invalidActivationResponse = {
  ...activationResponse,
  session: {
    ...activationResponse.session,
    // @ts-expect-error Activation responses reject unparsed signing-grant ids.
    signing_grant_id: 'grant-unparsed',
  },
} satisfies RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
void invalidActivationResponse;
