import type { StepUpMethodRunners } from './methodRunners';
import type {
  StepUpMethod,
  StepUpPolicy,
  StepUpWarmSessionAuthorization,
} from './types';

export class StepUpMethodSelectionError extends Error {
  readonly code: 'missing_step_up_runner' | 'unsupported_step_up_method';
  readonly method: StepUpMethod;

  constructor(
    code: StepUpMethodSelectionError['code'],
    method: StepUpMethod,
    message: string,
  ) {
    super(message);
    this.name = 'StepUpMethodSelectionError';
    this.code = code;
    this.method = method;
  }
}

type SelectableLane = {
  authMethod: 'passkey' | 'email_otp';
};

export type WarmSessionStepUpRoute = {
  method: 'warm_session';
  authorization: StepUpWarmSessionAuthorization;
};

export type PasskeyStepUpRoute<
  TLane extends SelectableLane,
  TOperation,
  TPasskeyAuthorization,
  TEmailOtpAuthorization,
> = {
  method: 'passkey';
  runner: NonNullable<
    StepUpMethodRunners<TLane, TOperation, TPasskeyAuthorization, TEmailOtpAuthorization>['passkey']
  >;
};

export type EmailOtpStepUpRoute<
  TLane extends SelectableLane,
  TOperation,
  TPasskeyAuthorization,
  TEmailOtpAuthorization,
> = {
  method: 'email_otp';
  runner: NonNullable<
    StepUpMethodRunners<TLane, TOperation, TPasskeyAuthorization, TEmailOtpAuthorization>['emailOtp']
  >;
};

export type StepUpMethodRoute<
  TLane extends SelectableLane,
  TOperation,
  TPasskeyAuthorization,
  TEmailOtpAuthorization,
> =
  | WarmSessionStepUpRoute
  | PasskeyStepUpRoute<TLane, TOperation, TPasskeyAuthorization, TEmailOtpAuthorization>
  | EmailOtpStepUpRoute<TLane, TOperation, TPasskeyAuthorization, TEmailOtpAuthorization>;

function methodFromPolicy<TLane extends SelectableLane>(
  selectedLane: TLane,
  policy: StepUpPolicy,
): StepUpMethod | 'warm_session' {
  if (policy.kind === 'reuse_warm_session') return 'warm_session';
  if (policy.kind === 'force_method') return policy.method;
  return selectedLane.authMethod;
}

export function selectStepUpMethod<
  TLane extends SelectableLane,
  TOperation,
  TPasskeyAuthorization,
  TEmailOtpAuthorization,
>(args: {
  selectedLane: TLane;
  policy: StepUpPolicy;
  methods: StepUpMethodRunners<TLane, TOperation, TPasskeyAuthorization, TEmailOtpAuthorization>;
}): StepUpMethodRoute<TLane, TOperation, TPasskeyAuthorization, TEmailOtpAuthorization> {
  if (args.policy.kind === 'reuse_warm_session') {
    return {
      method: 'warm_session',
      authorization: args.policy.authorization,
    };
  }
  const selectedMethod = methodFromPolicy(args.selectedLane, args.policy);
  if (selectedMethod === 'passkey') {
    if (!args.methods.passkey) {
      throw new StepUpMethodSelectionError(
        'missing_step_up_runner',
        selectedMethod,
        'Passkey step-up runner is required for this operation',
      );
    }
    return {
      method: 'passkey',
      runner: args.methods.passkey,
    };
  }
  if (selectedMethod === 'email_otp') {
    if (!args.methods.emailOtp) {
      throw new StepUpMethodSelectionError(
        'missing_step_up_runner',
        selectedMethod,
        'Email OTP step-up runner is required for this operation',
      );
    }
    return {
      method: 'email_otp',
      runner: args.methods.emailOtp,
    };
  }
  const unsupportedMethod = selectedMethod as Exclude<typeof selectedMethod, 'warm_session'>;
  throw new StepUpMethodSelectionError(
    'unsupported_step_up_method',
    unsupportedMethod,
    `Unsupported step-up method: ${unsupportedMethod}`,
  );
}
