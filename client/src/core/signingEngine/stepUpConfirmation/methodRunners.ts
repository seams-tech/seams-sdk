import type {
  EmailOtpConfirmPrompt,
  EmailOtpStepUpConfirmation,
  PasskeyPromptPlan,
  PasskeyStepUpConfirmation,
  StepUpMethod,
  StepUpPolicy,
} from './types';

export type PasskeyStepUpRunner<
  TLane extends { authMethod: string },
  TOperation,
  TAuthorization,
> = {
  method: 'passkey';
  prepare(input: {
    operation: TOperation;
    selectedLane: TLane;
    policy: StepUpPolicy;
  }): Promise<PasskeyPromptPlan>;
  complete(input: {
    operation: TOperation;
    selectedLane: TLane;
    policy: StepUpPolicy;
    prompt: PasskeyPromptPlan;
    confirmation: PasskeyStepUpConfirmation;
  }): Promise<TAuthorization>;
};

export type EmailOtpSigningChallenge = {
  challengeId: string;
  emailHint?: string;
};

export type EmailOtpStepUpRunner<
  TLane extends { authMethod: string },
  TOperation,
  TAuthorization,
> = {
  method: 'email_otp';
  prepareChallenge(input: {
    operation: TOperation;
    selectedLane: TLane;
    policy: StepUpPolicy;
  }): Promise<EmailOtpSigningChallenge>;
  resendChallenge?(input: {
    operation: TOperation;
    selectedLane: TLane;
    policy: StepUpPolicy;
    currentPrompt: EmailOtpConfirmPrompt;
  }): Promise<EmailOtpSigningChallenge>;
  complete(input: {
    operation: TOperation;
    selectedLane: TLane;
    policy: StepUpPolicy;
    prompt: EmailOtpConfirmPrompt;
    confirmation: EmailOtpStepUpConfirmation;
  }): Promise<TAuthorization>;
};

export type DeferredStepUpRunner<TMethod extends Exclude<StepUpMethod, 'passkey' | 'email_otp'>> = {
  method: TMethod;
};

export type StepUpMethodRunners<
  TLane extends { authMethod: string },
  TOperation,
  TPasskeyAuthorization,
  TEmailOtpAuthorization,
> = {
  passkey?: PasskeyStepUpRunner<TLane, TOperation, TPasskeyAuthorization>;
  emailOtp?: EmailOtpStepUpRunner<TLane, TOperation, TEmailOtpAuthorization>;
  authenticatorOtp?: DeferredStepUpRunner<'authenticator_otp'>;
  magicLink?: DeferredStepUpRunner<'magic_link'>;
  password?: DeferredStepUpRunner<'password'>;
};
