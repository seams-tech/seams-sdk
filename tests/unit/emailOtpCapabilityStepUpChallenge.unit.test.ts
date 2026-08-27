import { expect, test } from '@playwright/test';
import {
  createEmailOtpEcdsaTransactionSigningBridge,
  emailOtpEcdsaCapabilityStepUpAuthority,
  type EmailOtpEcdsaChallengeAuthority,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import { resolveEvmFamilyTransactionStepUp } from '@/core/signingEngine/flows/signEvmFamily/authPlanning';
import { buildEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaWalletSessionRefFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';

// Auth-neutral Email OTP material has no warm signing lane and no reauth
// anchor, so the capability itself is the authority a step-up proves against.
// Getting this wrong sends the OTP to a mailbox that is not the one bound to
// the material being signed with, which is why every disagreement is a hard
// failure rather than a fallback.

const OPERATION_FINGERPRINT_DIGEST = parseDigestB64u('A'.repeat(43));
const OPERATION_FINGERPRINT = `sha256:${OPERATION_FINGERPRINT_DIGEST}`;

async function capabilityFor(factor: 'passkey' | 'email_otp') {
  return await canonicalEvmFamilyEcdsaSigningCapabilityFixture(factor);
}

function deliveredChallenge() {
  return {
    challengeId: 'capability-step-up-challenge',
    emailHint: 'a***@x.test',
    delivery: { kind: 'provider' as const, status: 'sent' as const, emailHint: 'a***@x.test' },
  };
}

test.describe('Email OTP capability step-up challenge', () => {
  test('mints a challenge bound to the capability and the exact operation', async () => {
    const { capability, manifest } = await capabilityFor('email_otp');
    const stepUpAuthority = emailOtpEcdsaCapabilityStepUpAuthority({
      capability,
      materialActivation: manifest.activation.materialActivation,
      operationFingerprint: OPERATION_FINGERPRINT,
    });

    const seen: Array<{
      authority: EmailOtpEcdsaChallengeAuthority;
      operationFingerprintDigest: typeof OPERATION_FINGERPRINT_DIGEST;
    }> = [];
    const bridge = createEmailOtpEcdsaTransactionSigningBridge({
      walletId: String(manifest.signer.walletId),
      walletSession: ecdsaWalletSessionRefFixture(manifest),
      chain: 'evm',
      authority: stepUpAuthority,
      operationFingerprintDigest: OPERATION_FINGERPRINT_DIGEST,
      requestEmailOtpTransactionSigningChallenge: async (args) => {
        seen.push(args);
        // The full production challenge shape: `delivery` is required, and the
        // bridge derives the demo-code hint from it after the mint.
        return deliveredChallenge();
      },
    });

    const challenge = await bridge.challenge();

    expect(challenge.challengeId).toBe('capability-step-up-challenge');
    expect(seen).toHaveLength(1);
    const crossed = seen[0]!.authority;
    expect(crossed.kind).toBe('capability_step_up');
    if (crossed.kind !== 'capability_step_up') throw new Error('expected a capability step-up');
    // Provider identity and email binding come from the capability, not from
    // the confirmation plan or the caller.
    expect(crossed.capabilityAuthority.factor.kind).toBe('email_otp');
    expect(crossed.capabilityAuthority.verifier.emailHashHex).toBe('email-hash');
    expect(String(crossed.materialActivation.activationId)).toBe(
      String(manifest.activation.materialActivation.activationId),
    );
    expect(crossed.operationFingerprint).toBe(OPERATION_FINGERPRINT);
    expect(seen[0]!.operationFingerprintDigest).toBe(OPERATION_FINGERPRINT_DIGEST);
  });

  test('rejects a caller-supplied authority that disagrees with the capability', async () => {
    const { capability, manifest } = await capabilityFor('email_otp');
    const otherWalletAuthority = buildEmailOtpWalletAuthAuthority({
      walletId: String(manifest.signer.walletId),
      provider: 'google',
      providerUserId: `google:${String(manifest.signer.walletId)}`,
      // A different mailbox than the capability is bound to.
      emailHashHex: 'someone-elses-email-hash',
    });

    expect(() =>
      emailOtpEcdsaCapabilityStepUpAuthority({
        capability,
        materialActivation: manifest.activation.materialActivation,
        operationFingerprint: OPERATION_FINGERPRINT,
        claimedAuthority: otherWalletAuthority,
      }),
    ).toThrow('does not match the selected capability');
  });

  test('rejects a capability whose factor is not Email OTP', async () => {
    const { capability, manifest } = await capabilityFor('passkey');

    expect(() =>
      emailOtpEcdsaCapabilityStepUpAuthority({
        capability,
        materialActivation: manifest.activation.materialActivation,
        operationFingerprint: OPERATION_FINGERPRINT,
      }),
    ).toThrow('requires an Email OTP capability authority');
  });

  test('rejects material the selected capability does not name', async () => {
    const { capability, manifest } = await capabilityFor('email_otp');

    expect(() =>
      emailOtpEcdsaCapabilityStepUpAuthority({
        capability,
        materialActivation: buildMpcMaterialActivationRefFixture(
          'capability-step-up-other-activation',
          String(manifest.signer.walletId),
        ),
        operationFingerprint: OPERATION_FINGERPRINT,
      }),
    ).toThrow('material activation does not match the selected capability');
  });

  test('requires an operation fingerprint to bind the challenge to', async () => {
    const { capability, manifest } = await capabilityFor('email_otp');

    expect(() =>
      emailOtpEcdsaCapabilityStepUpAuthority({
        capability,
        materialActivation: manifest.activation.materialActivation,
        operationFingerprint: '   ',
      }),
    ).toThrow('requires an operation fingerprint');
  });

  test('uses a Passkey capability when the account primary method is Email OTP', async () => {
    const { capability, manifest } = await capabilityFor('passkey');
    const result = await resolveEvmFamilyTransactionStepUp({
      deps: {},
      confirmedDeps: {},
      walletSession: ecdsaWalletSessionRefFixture(manifest),
      chain: 'evm',
      chainTarget: manifest.signer.scope.targetMemberships[0],
      accountAuth: {
        primaryAuthMethod: 'email_otp',
        linkedAuthMethods: ['email_otp', 'passkey'],
      },
      senderSignatureAlgorithm: 'secp256k1',
      ecdsaAuthorization: 'operation_step_up',
      capability,
      materialActivation: manifest.activation.materialActivation,
      operationFingerprint: OPERATION_FINGERPRINT,
      operationFingerprintDigest: OPERATION_FINGERPRINT_DIGEST,
    });

    expect(result.signingAuthPlan).toEqual({ kind: 'passkeyReauth', method: 'passkey' });
    expect(result.emailOtpSigning).toBeUndefined();
  });

  test('uses an Email OTP capability when the account primary method is Passkey', async () => {
    const { capability, manifest } = await capabilityFor('email_otp');
    const seen: EmailOtpEcdsaChallengeAuthority[] = [];
    const result = await resolveEvmFamilyTransactionStepUp({
      deps: {},
      confirmedDeps: {
        requestEmailOtpTransactionSigningChallenge: async (args) => {
          seen.push(args.authority);
          return deliveredChallenge();
        },
      },
      walletSession: ecdsaWalletSessionRefFixture(manifest),
      chain: 'evm',
      chainTarget: manifest.signer.scope.targetMemberships[0],
      accountAuth: {
        primaryAuthMethod: 'passkey',
        linkedAuthMethods: ['passkey', 'email_otp'],
      },
      senderSignatureAlgorithm: 'secp256k1',
      ecdsaAuthorization: 'operation_step_up',
      capability,
      materialActivation: manifest.activation.materialActivation,
      operationFingerprint: OPERATION_FINGERPRINT,
      operationFingerprintDigest: OPERATION_FINGERPRINT_DIGEST,
    });

    expect(result.signingAuthPlan).toEqual({ kind: 'emailOtpReauth', method: 'email_otp' });
    expect(result.emailOtpSigning).toBeDefined();
    await result.emailOtpSigning!.prepare();
    expect(seen).toHaveLength(1);
    expect(seen[0]?.kind).toBe('capability_step_up');
  });
});
