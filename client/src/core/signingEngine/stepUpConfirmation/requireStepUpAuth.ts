import { buildEmailOtpSigningPrompt } from './otpPrompt/signingPrompt';
import { selectStepUpMethod } from './methodSelection';
import type { StepUpMethodRunners } from './methodRunners';
import type {
  EmailOtpConfirmPrompt,
  StepUpAuthorizationResult,
  StepUpPolicy,
} from './types';

type SelectableLane = {
  authMethod: 'passkey' | 'email_otp';
};

export type RequireStepUpAuthRequest<
  TLane extends SelectableLane,
  TOperation,
  TPasskeyAuthorization,
  TEmailOtpAuthorization,
> = {
  operation: TOperation;
  selectedLane: TLane;
  policy: StepUpPolicy;
  confirmation: {
    confirmPasskey(input: { prompt: { title?: string; body?: string } }): Promise<{
      credential: unknown;
    }>;
    confirmEmailOtp(input: { prompt: EmailOtpConfirmPrompt }): Promise<{
      otpCode: string;
    }>;
  };
  methods: StepUpMethodRunners<TLane, TOperation, TPasskeyAuthorization, TEmailOtpAuthorization>;
};

export async function requireStepUpAuth<
  TLane extends SelectableLane,
  TOperation,
  TPasskeyAuthorization,
  TEmailOtpAuthorization,
>(
  args: RequireStepUpAuthRequest<
    TLane,
    TOperation,
    TPasskeyAuthorization,
    TEmailOtpAuthorization
  >,
): Promise<StepUpAuthorizationResult<TPasskeyAuthorization, TEmailOtpAuthorization>> {
  const route = selectStepUpMethod({
    selectedLane: args.selectedLane,
    policy: args.policy,
    methods: args.methods,
  });

  if (route.method === 'warm_session') {
    return {
      method: 'warm_session',
      authorization: route.authorization,
    };
  }

  if (route.method === 'passkey') {
    const prompt = await route.runner.prepare({
      operation: args.operation,
      selectedLane: args.selectedLane,
      policy: args.policy,
    });
    const confirmation = await args.confirmation.confirmPasskey({ prompt });
    return {
      method: 'passkey',
      authorization: await route.runner.complete({
        operation: args.operation,
        selectedLane: args.selectedLane,
        policy: args.policy,
        prompt,
        confirmation,
      }),
    };
  }

  const challenge = await route.runner.prepareChallenge({
    operation: args.operation,
    selectedLane: args.selectedLane,
    policy: args.policy,
  });
  const prompt = buildEmailOtpSigningPrompt({
    challenge,
    resend: route.runner.resendChallenge
      ? async () =>
          await route.runner.resendChallenge!({
            operation: args.operation,
            selectedLane: args.selectedLane,
            policy: args.policy,
            currentPrompt: promptRef.prompt,
          })
      : undefined,
  });
  const promptRef: { prompt: EmailOtpConfirmPrompt } = { prompt };
  const confirmation = await args.confirmation.confirmEmailOtp({ prompt });
  return {
    method: 'email_otp',
    authorization: await route.runner.complete({
      operation: args.operation,
      selectedLane: args.selectedLane,
      policy: args.policy,
      prompt,
      confirmation,
    }),
  };
}
