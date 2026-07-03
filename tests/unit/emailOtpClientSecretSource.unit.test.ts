import { expect, test } from '@playwright/test';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';

import {
  EMAIL_OTP_ED25519_RECOVERY_CODE_BINDING_DIGEST_KIND,
  recoveryCodeBindingDigestForEmailOtpMaterial,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/clientSecretSource';

async function digestCanonicalInput(input: Record<string, unknown>): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input)));
}

test.describe('Email OTP client secret source bindings', () => {
  test('binds Ed25519 recovery-code material to providerUserId', async () => {
    const actual = await recoveryCodeBindingDigestForEmailOtpMaterial({
      providerUserId: 'google:alice',
      rpId: 'example.localhost',
      nearAccountId: 'alice.testnet',
    });

    const expected = await digestCanonicalInput({
      kind: EMAIL_OTP_ED25519_RECOVERY_CODE_BINDING_DIGEST_KIND,
      nearAccountId: 'alice.testnet',
      providerUserId: 'google:alice',
      rpId: 'example.localhost',
    });
    const staleAuthSubjectIdDigest = await digestCanonicalInput({
      authSubjectId: 'google:alice',
      kind: EMAIL_OTP_ED25519_RECOVERY_CODE_BINDING_DIGEST_KIND,
      nearAccountId: 'alice.testnet',
      rpId: 'example.localhost',
    });

    expect(EMAIL_OTP_ED25519_RECOVERY_CODE_BINDING_DIGEST_KIND).toBe(
      'email_otp_ed25519_recovery_code_binding_v2',
    );
    expect(actual).toBe(expected);
    expect(actual).not.toBe(staleAuthSubjectIdDigest);
  });
});
