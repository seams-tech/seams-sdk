import type {
  ThresholdEcdsaExplicitKeyExportActivationResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaEmailOtpExportActivationRequest,
  ThresholdEcdsaPasskeyExportActivationRequest,
} from './ecdsaSessionProvision';
import type { EmailOtpEcdsaExplicitExportBootstrapResult } from './ecdsaBootstrap';

type ThresholdEcdsaTransactionActivationRequest = Exclude<
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaPasskeyExportActivationRequest
>;

declare const explicitExportResult: ThresholdEcdsaExplicitKeyExportActivationResult;
declare const explicitExportRequest: ThresholdEcdsaPasskeyExportActivationRequest;
declare const emailOtpExplicitExportResult: EmailOtpEcdsaExplicitExportBootstrapResult;
declare const emailOtpExplicitExportRequest: ThresholdEcdsaEmailOtpExportActivationRequest;

// @ts-expect-error Ephemeral export material cannot become a transaction bootstrap result.
const invalidTransactionBootstrap: ThresholdEcdsaSessionBootstrapResult = explicitExportResult;
void invalidTransactionBootstrap;

// @ts-expect-error Explicit export activation cannot enter transaction provisioning.
const invalidTransactionActivation: ThresholdEcdsaTransactionActivationRequest =
  explicitExportRequest;
void invalidTransactionActivation;

// @ts-expect-error Email OTP export activation cannot enter transaction provisioning.
const invalidEmailOtpTransactionActivation: ThresholdEcdsaTransactionActivationRequest =
  emailOtpExplicitExportRequest;
void invalidEmailOtpTransactionActivation;

// @ts-expect-error Email OTP export results are explicit wrappers, not transaction bootstraps.
const invalidEmailOtpTransactionBootstrap: ThresholdEcdsaSessionBootstrapResult =
  emailOtpExplicitExportResult;
void invalidEmailOtpTransactionBootstrap;

const invalidTransactionSpread = {
  ...explicitExportResult,
  purpose: 'transaction_signing' as const,
};

// @ts-expect-error Changing the discriminator cannot create a transaction bootstrap result.
const invalidSpreadBootstrap: ThresholdEcdsaSessionBootstrapResult = invalidTransactionSpread;
void invalidSpreadBootstrap;
