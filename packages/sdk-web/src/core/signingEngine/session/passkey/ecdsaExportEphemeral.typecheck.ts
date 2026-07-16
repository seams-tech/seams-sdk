import type {
  ThresholdEcdsaExplicitKeyExportActivationResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaPasskeyExportActivationRequest,
} from './ecdsaSessionProvision';

type ThresholdEcdsaTransactionActivationRequest = Exclude<
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaPasskeyExportActivationRequest
>;

declare const explicitExportResult: ThresholdEcdsaExplicitKeyExportActivationResult;
declare const explicitExportRequest: ThresholdEcdsaPasskeyExportActivationRequest;

// @ts-expect-error Ephemeral export material cannot become a transaction bootstrap result.
const invalidTransactionBootstrap: ThresholdEcdsaSessionBootstrapResult = explicitExportResult;
void invalidTransactionBootstrap;

// @ts-expect-error Explicit export activation cannot enter transaction provisioning.
const invalidTransactionActivation: ThresholdEcdsaTransactionActivationRequest =
  explicitExportRequest;
void invalidTransactionActivation;

const invalidTransactionSpread = {
  ...explicitExportResult,
  purpose: 'transaction_signing' as const,
};

// @ts-expect-error Changing the discriminator cannot create a transaction bootstrap result.
const invalidSpreadBootstrap: ThresholdEcdsaSessionBootstrapResult = invalidTransactionSpread;
void invalidSpreadBootstrap;
