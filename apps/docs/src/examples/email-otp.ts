import type { SeamsWeb } from '@seams/wallet';

type StartResult = Awaited<ReturnType<SeamsWeb['auth']['beginGoogleEmailOtpWalletAuth']>>;
type AuthFlow = Extract<StartResult, { ok: true }>['value'];
type LoginFlow = Extract<AuthFlow, { mode: 'login' }>;
type SubmitResult = Awaited<ReturnType<LoginFlow['submit']>>;
type SubmitSuccess = Extract<SubmitResult, { ok: true }>['value'];

export async function startGoogleEmailOtpLogin(
  seams: SeamsWeb,
  googleIdToken: string,
): Promise<LoginFlow> {
  const started = await seams.auth.beginGoogleEmailOtpWalletAuth({
    idToken: googleIdToken,
    mode: 'login',
  });
  if (!started.ok) {
    throw new Error(started.error.message);
  }
  if (started.value.mode !== 'login') {
    await started.value.cancel();
    throw new Error('This Google account needs wallet registration');
  }
  return started.value;
}

export async function submitGoogleEmailOtp(
  flow: LoginFlow,
  otpCode: string,
): Promise<SubmitSuccess> {
  const submitted = await flow.submit({ otpCode });
  if (!submitted.ok) {
    throw new Error(submitted.error.message);
  }
  return submitted.value;
}
