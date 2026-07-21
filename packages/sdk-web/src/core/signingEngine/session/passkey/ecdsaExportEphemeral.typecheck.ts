import type {
  ThresholdEcdsaExplicitKeyExportActivationResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../threshold/ecdsa/activation';
import type {
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaEmailOtpActivationRequest,
  ThresholdEcdsaEmailOtpExportActivationRequest,
  ThresholdEcdsaPasskeyExportActivationRequest,
} from './ecdsaSessionProvision';
import type {
  EmailOtpEcdsaExactBootstrapRequest,
  EmailOtpEcdsaExplicitExportBootstrapRequest,
  EmailOtpEcdsaExplicitExportBootstrapResult,
} from './ecdsaBootstrap';
import type {
  ActivateEcdsaSessionRequest,
  ActivateEmailOtpExplicitExportBootstrapSessionRequest,
} from '../../threshold/ecdsa/activation';

type ThresholdEcdsaTransactionActivationRequest = Exclude<
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaPasskeyExportActivationRequest
>;

declare const explicitExportResult: ThresholdEcdsaExplicitKeyExportActivationResult;
declare const explicitExportRequest: ThresholdEcdsaPasskeyExportActivationRequest;
declare const emailOtpExplicitExportResult: EmailOtpEcdsaExplicitExportBootstrapResult;
declare const emailOtpExplicitExportRequest: ThresholdEcdsaEmailOtpExportActivationRequest;
declare const emailOtpTransactionRequest: ThresholdEcdsaEmailOtpActivationRequest;
declare const emailOtpExactBootstrapRequest: EmailOtpEcdsaExactBootstrapRequest;
declare const emailOtpActivationRequest: ActivateEcdsaSessionRequest;

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

// @ts-expect-error Transaction worker handles cannot enter Email OTP export activation.
const invalidEmailOtpExportRequest: ThresholdEcdsaEmailOtpExportActivationRequest =
  emailOtpTransactionRequest;
void invalidEmailOtpExportRequest;

// @ts-expect-error General Email OTP bootstrap requests do not prove an export handle.
const invalidEmailOtpExportBootstrapRequest: EmailOtpEcdsaExplicitExportBootstrapRequest =
  emailOtpExactBootstrapRequest;
void invalidEmailOtpExportBootstrapRequest;

// @ts-expect-error General activation requests do not prove an export handle.
const invalidEmailOtpExportBootstrapActivation: ActivateEmailOtpExplicitExportBootstrapSessionRequest =
  emailOtpActivationRequest;
void invalidEmailOtpExportBootstrapActivation;

const invalidTransactionSpread = {
  ...explicitExportResult,
  purpose: 'transaction_signing' as const,
};

// @ts-expect-error Changing the discriminator cannot create a transaction bootstrap result.
const invalidSpreadBootstrap: ThresholdEcdsaSessionBootstrapResult = invalidTransactionSpread;
void invalidSpreadBootstrap;
