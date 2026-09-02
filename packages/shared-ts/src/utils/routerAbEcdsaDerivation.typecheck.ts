import type { ThresholdEcdsaSessionId } from './domainIds';
import type {
  RouterAbEcdsaDerivationActivationCommitQueryResultV1,
  RouterAbEcdsaDerivationActivationPrepareResultV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  RouterAbEcdsaPostRegistrationSessionPolicyV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaRegistrationActivationRequestV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from './routerAbEcdsaDerivation';
import type { RuntimePolicyScope } from '../threshold/signingRootScope';
import type { CorrelationId } from './canonicalPrimitives';
import type { WalletSessionMintId } from '../authorization/capabilityKinds';

declare const thresholdSessionId: ThresholdEcdsaSessionId;
declare const walletSessionMintId: WalletSessionMintId;
declare const runtimePolicyScope: RuntimePolicyScope;
declare const activationResponse: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
declare const activationCorrelationId: CorrelationId;
declare const clientActivationFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
declare const activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;

const sessionPolicy = {
  threshold_session_id: thresholdSessionId,
  wallet_session_mint_id: walletSessionMintId,
  ttl_ms: 60_000,
  remaining_uses: 2,
  runtime_policy_scope: runtimePolicyScope,
} satisfies RouterAbEcdsaPostRegistrationSessionPolicyV1;
void sessionPolicy;

const registrationActivation = {
  registrationCeremonyId: 'registration-ceremony',
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_activation_v1',
    activationCorrelationId,
    publicFacts: clientActivationFacts,
  },
} satisfies RouterAbEcdsaRegistrationActivationRequestV1;
void registrationActivation;

const missingActivationCorrelation = {
  registrationCeremonyId: 'registration-ceremony',
  // @ts-expect-error Registration activation requires a browser journal correlation.
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_activation_v1',
    publicFacts: clientActivationFacts,
  },
} satisfies RouterAbEcdsaRegistrationActivationRequestV1;
void missingActivationCorrelation;

const activationPrepareResult = {
  activation_correlation_id: activationCorrelationId,
  activation_request_digest: { bytes: new Array<number>(32).fill(1) },
} satisfies RouterAbEcdsaDerivationActivationPrepareResultV1;
void activationPrepareResult;

const committedActivationQueryResult = {
  kind: 'committed',
  receipt: activationReceipt,
} satisfies RouterAbEcdsaDerivationActivationCommitQueryResultV1;
void committedActivationQueryResult;

const invalidCommittedActivationQueryResult = {
  kind: 'committed',
  receipt: activationReceipt,
  activation_correlation_id: activationCorrelationId,
  // @ts-expect-error A committed query result cannot carry absence coordinates.
} satisfies RouterAbEcdsaDerivationActivationCommitQueryResultV1;
void invalidCommittedActivationQueryResult;

const invalidNotCommittedActivationQueryResult = {
  kind: 'not_committed',
  activation_correlation_id: activationCorrelationId,
  activation_request_digest: { bytes: new Array<number>(32).fill(1) },
  receipt: activationReceipt,
  // @ts-expect-error An uncommitted query result cannot carry a receipt.
} satisfies RouterAbEcdsaDerivationActivationCommitQueryResultV1;
void invalidNotCommittedActivationQueryResult;
