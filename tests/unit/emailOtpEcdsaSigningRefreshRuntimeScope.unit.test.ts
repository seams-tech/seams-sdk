import { expect, test } from '@playwright/test';
import type { ActiveEcdsaCapabilityManifest } from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import {
  type ActiveEcdsaCapabilityRuntimeResolver,
  type ActiveEcdsaCapabilityRuntimeResolution,
} from '@/core/signingEngine/session/material/activeEcdsaCapabilityRuntime';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import type { CurrentEcdsaSealedSessionRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { buildBaseEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildEvmTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import { requireResolvedEvmFamilyEcdsaSigningLane } from '@/core/signingEngine/flows/signEvmFamily/ecdsaLanes';
import { emailOtpEcdsaSigningSessionAuthLane } from '@/core/signingEngine/session/emailOtp/ecdsaSigningSessionAuthority';
import type { ExactEvmFamilyWalletSessionAuthorization } from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import {
  loginWithEmailOtpEcdsaCapabilityForSigning,
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
} from '@/core/signingEngine/session/emailOtp/ecdsaLogin';
import {
  isEmailOtpWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { EcdsaCommittedLane } from '@/core/signingEngine/flows/signEvmFamily/ecdsaSelection';
import {
  canonicalEvmFamilyEcdsaSigningCapabilityFixture,
  ecdsaWalletSessionRefFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture } from './helpers/exactEvmFamilyWalletSessionAuthorization.fixtures';

const INTERNAL_PORT_REACHED = 'internal ECDSA login port reached';

let capturedLoginRequest: LoginEmailOtpEcdsaCapabilityArgs | undefined;

async function captureInternalLoginRequest(
  request: LoginEmailOtpEcdsaCapabilityArgs,
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  capturedLoginRequest = request;
  throw new Error(INTERNAL_PORT_REACHED);
}

function fixtureRuntimeResolver(args: {
  manifest: ActiveEcdsaCapabilityManifest;
  record: CurrentEcdsaSealedSessionRecord;
}): ActiveEcdsaCapabilityRuntimeResolver {
  return async ({ walletId, chainTarget }): Promise<ActiveEcdsaCapabilityRuntimeResolution> => {
    const resolution = resolveExactEcdsaSealedRuntime({
      manifest: args.manifest,
      walletId,
      chainTarget,
      sealedRecords: [args.record],
    });
    if (resolution.kind !== 'resolved') {
      return { kind: 'blocked', reason: resolution.reason };
    }
    return { kind: 'resolved', manifest: args.manifest, runtime: resolution.runtime };
  };
}

type CapabilityFixture = Awaited<
  ReturnType<typeof canonicalEvmFamilyEcdsaSigningCapabilityFixture>
>;
function committedEmailOtpLaneFixture(args: {
  fixture: CapabilityFixture;
  authorization: ExactEvmFamilyWalletSessionAuthorization;
}): EcdsaCommittedLane<EmailOtpWalletAuthAuthority> {
  const { manifest } = args.fixture;
  if (
    args.authorization.runtime.authBinding.kind !== 'email_otp' ||
    !isEmailOtpWalletAuthAuthority(args.authorization.runtime.authBinding.emailOtpAuthority)
  ) {
    throw new Error('ECDSA Email OTP fixture authority is not Email OTP');
  }
  const authority = args.authorization.runtime.authBinding.emailOtpAuthority;
  const publicFacts = manifest.durableMaterial.roleLocalPublicFacts;
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: manifest.signer.walletId,
    ecdsaThresholdKeyId: publicFacts.ecdsaThresholdKeyId,
    signingRootId: publicFacts.signingRootId,
    signingRootVersion: publicFacts.signingRootVersion,
    participantIds: publicFacts.participantIds,
    thresholdOwnerAddress: publicFacts.ethereumAddress,
  });
  const lane = buildEvmTransactionSigningLane({
    key,
    materialActivation: manifest.durableMaterial.materialActivation,
    keyHandle: publicFacts.keyHandle,
    walletId: manifest.signer.walletId,
    auth: {
      kind: 'email_otp',
      providerSubjectId: authority.factor.providerUserId,
    },
    authorization: args.authorization,
    chainTarget: publicFacts.chainTarget,
  });
  return {
    lane: requireResolvedEvmFamilyEcdsaSigningLane({
      lane,
      chain: publicFacts.chainTarget.kind,
      context: 'Email OTP signing refresh fixture',
    }),
    authority,
    authorization: args.authorization,
    authLane: emailOtpEcdsaSigningSessionAuthLane(args.authorization),
  };
}

test('Email OTP ECDSA signing refresh forwards the exact sealed runtime scope', async () => {
  capturedLoginRequest = undefined;
  const fixture = await canonicalEvmFamilyEcdsaSigningCapabilityFixture('email_otp');
  const chainTarget = fixture.manifest.signer.scope.targetMemberships[0];
  if (!chainTarget) throw new Error('ECDSA fixture is missing a target membership');
  const thresholdSessionId = 'ec-session-refresh-scope';
  const sealedRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
    manifest: fixture.manifest,
    chainTarget,
    thresholdSessionId,
  });
  const runtimeResolution = resolveExactEcdsaSealedRuntime({
    manifest: fixture.manifest,
    walletId: fixture.manifest.signer.walletId,
    chainTarget,
    sealedRecords: [sealedRecord],
  });
  if (runtimeResolution.kind !== 'resolved') {
    throw new Error('ECDSA sealed runtime fixture did not resolve');
  }
  const authorization = await buildExactEmailOtpEvmFamilyWalletSessionAuthorizationFixture({
    capability: fixture.capability,
    runtime: runtimeResolution.runtime,
    label: 'refresh-scope',
  });
  const committedLane = committedEmailOtpLaneFixture({
    fixture,
    authorization,
  });
  const resolveCurrentEcdsaCapabilityRuntime = fixtureRuntimeResolver({
    manifest: fixture.manifest,
    record: sealedRecord,
  });

  await expect(
    loginWithEmailOtpEcdsaCapabilityForSigning(
      {
        walletSession: ecdsaWalletSessionRefFixture(fixture.manifest),
        chainTarget,
        challengeId: 'email-otp-refresh-challenge',
        otpCode: '123456',
        committedLane,
        remainingUses: 3,
      },
      {
        requireRelayUrl: () => 'https://relay.example.test',
        resolveCurrentEcdsaCapabilityRuntime,
        loginWithEcdsaCapabilityInternal: captureInternalLoginRequest,
      },
    ),
  ).rejects.toThrow(INTERNAL_PORT_REACHED);

  const request = capturedLoginRequest;
  if (!request) throw new Error('ECDSA login internal port was not reached');
  expect(request.runtimePolicyScope).toEqual(runtimeResolution.runtime.runtimePolicyScope);
});
