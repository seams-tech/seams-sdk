import type {
  GoogleEmailOtpWalletAuthLoginFlow,
  GoogleEmailOtpWalletAuthSubmitSuccess,
  SeamsWeb,
} from '@seams/wallet';

export async function startGoogleEmailOtpLogin(
  seams: SeamsWeb,
  googleIdToken: string,
): Promise<GoogleEmailOtpWalletAuthLoginFlow> {
  const started = await seams.auth.beginGoogleEmailOtpWalletAuth({
    idToken: googleIdToken,
    mode: 'login',
    loginTarget: { kind: 'discoverable' },
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
  flow: GoogleEmailOtpWalletAuthLoginFlow,
  otpCode: string,
): Promise<GoogleEmailOtpWalletAuthSubmitSuccess> {
  const submitted = await flow.submit({ otpCode });
  if (!submitted.ok) {
    throw new Error(submitted.error.message);
  }
  return submitted.value;
}
