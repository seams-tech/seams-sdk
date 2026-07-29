import { expect, test } from '@playwright/test';
import {
  createEmailOtpEcdsaTransactionSigningBridge,
  emailOtpEcdsaCapabilityStepUpAuthority,
  type EmailOtpEcdsaChallengeAuthority,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import { buildPersistedEcdsaRoleLocalMaterial } from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSigningCapability';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { ecdsaCapabilityActivationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

// Auth-neutral Email OTP material has no warm signing lane and no reauth
// anchor, so the capability itself is the authority a step-up proves against.
// Getting this wrong sends the OTP to a mailbox that is not the one bound to
// the material being signed with, which is why every disagreement is a hard
// failure rather than a fallback.

const OPERATION_FINGERPRINT = 'sha256:capability-step-up-operation-1';

function capabilityFor(factor: 'passkey' | 'email_otp'): {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  manifest: ActiveEcdsaCapabilityManifest;
  authority: WalletAuthAuthority;
} {
  const manifest = ecdsaCapabilityActivationLookupFixture().manifest;
  const walletId = String(manifest.signer.walletId);
  const authority =
    factor === 'email_otp'
      ? buildEmailOtpWalletAuthAuthority({
          walletId,
          provider: 'google',
          providerUserId: `google:${walletId}`,
          emailHashHex: 'email-hash',
        })
      : buildPasskeyWalletAuthAuthority({
          walletId,
          rpId: 'example.localhost',
          credentialIdB64u: 'credential-passkey-fixture',
        });
  return {
    manifest,
    authority,
    capability: {
      kind: 'canonical_evm_family_ecdsa_signing_capability',
      authority,
      manifest,
      material: buildPersistedEcdsaRoleLocalMaterial({
        authority: manifest.signer.authority,
        materialActivation: manifest.durableMaterial.materialActivation,
        publicFacts: manifest.durableMaterial.roleLocalPublicFacts,
      }),
    } as CanonicalEvmFamilyEcdsaSigningCapability,
  };
}

test.describe('Email OTP capability step-up challenge', () => {
  test('mints a challenge bound to the capability and the exact operation', async () => {
    const { capability, manifest } = capabilityFor('email_otp');
    const stepUpAuthority = emailOtpEcdsaCapabilityStepUpAuthority({
      capability,
      materialActivation: manifest.activation.materialActivation,
      operationFingerprint: OPERATION_FINGERPRINT,
    });

    const seen: EmailOtpEcdsaChallengeAuthority[] = [];
    const bridge = createEmailOtpEcdsaTransactionSigningBridge({
      walletId: String(manifest.signer.walletId),
      walletSession: { walletId: String(manifest.signer.walletId) } as never,
      chain: 'evm',
      authority: stepUpAuthority,
      requestEmailOtpTransactionSigningChallenge: async (args) => {
        seen.push(args.authority);
        return {
          challengeId: 'capability-step-up-challenge',
          emailHint: 'a***@x.test',
        } as never;
      },
    });

    const challenge = await bridge.challenge();

    expect(challenge.challengeId).toBe('capability-step-up-challenge');
    expect(seen).toHaveLength(1);
    const crossed = seen[0]!;
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
  });

  test('rejects a caller-supplied authority that disagrees with the capability', () => {
    const { capability, manifest } = capabilityFor('email_otp');
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

  test('rejects a capability whose factor is not Email OTP', () => {
    const { capability, manifest } = capabilityFor('passkey');

    expect(() =>
      emailOtpEcdsaCapabilityStepUpAuthority({
        capability,
        materialActivation: manifest.activation.materialActivation,
        operationFingerprint: OPERATION_FINGERPRINT,
      }),
    ).toThrow('requires an Email OTP capability authority');
  });

  test('rejects material the selected capability does not name', () => {
    const { capability, manifest } = capabilityFor('email_otp');

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

  test('requires an operation fingerprint to bind the challenge to', () => {
    const { capability, manifest } = capabilityFor('email_otp');

    expect(() =>
      emailOtpEcdsaCapabilityStepUpAuthority({
        capability,
        materialActivation: manifest.activation.materialActivation,
        operationFingerprint: '   ',
      }),
    ).toThrow('requires an operation fingerprint');
  });
});
