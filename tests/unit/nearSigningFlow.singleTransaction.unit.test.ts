import { expect, test } from '@playwright/test';
import { ActionType } from '@/core/types/actions';
import { signNearWithUiConfirm } from '@/core/signingEngine/flows/signNear/nearSigningFlow';
import { emitNearSigningConfirmationProgress } from '@/core/signingEngine/flows/signNear/signTransactions';
import { signingAuthPlanForNearMaterialRequirement } from '@/core/signingEngine/flows/signNear/requireNearStepUpAuth';
import { SigningEventPhase, type SigningFlowEvent } from '@/core/types/sdkSentEvents';
import {
  authorizedPasskeyEd25519AvailableLane,
  availableLaneEd25519Authorization,
} from './helpers/availableSigningLanes.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { buildEmailOtpEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';

test.describe('NEAR transaction signing shape', () => {
  test('rejects multi-transaction signing before signing-session admission', async () => {
    await expect(
      signNearWithUiConfirm({
        chain: 'near',
        kind: 'transactionWithActions',
        payload: {
          nearAccount: { accountId: 'alice.testnet' },
          rpcCall: { nearAccountId: 'alice.testnet' },
          transactions: [
            {
              receiverId: 'contract-a.testnet',
              actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
            },
            {
              receiverId: 'contract-b.testnet',
              actions: [{ action_type: ActionType.Transfer, deposit: '2' }],
            },
          ],
        },
      } as never),
    ).rejects.toThrow('exactly one NEAR transaction is supported');
  });

  test('reports Passkey operation-step-up prompt lifecycle for an exact shared Ed25519 lane', () => {
    const materialActivation = buildMpcMaterialActivationRefFixture(
      'near-signing-progress-passkey',
      'frost-vermillion-k7p9m2',
    );
    const authorization = availableLaneEd25519Authorization({
      walletId: 'frost-vermillion-k7p9m2',
      identitySeed: 'near-signing-progress-passkey',
      authMethod: 'passkey',
      materialActivation,
    });
    const lane = authorizedPasskeyEd25519AvailableLane({
      authorization,
      materialActivation,
    });
    const signingAuthPlan = signingAuthPlanForNearMaterialRequirement(lane.auth);
    const events: SigningFlowEvent[] = [];
    const progressArgs = {
      onEvent: events.push.bind(events),
      nearAccountId: lane.nearAccountId,
      signingAuthPlan,
    };

    emitNearSigningConfirmationProgress(progressArgs, {
      requestId: 'near-passkey-progress',
      step: 1,
      phase: 'auth.passkey.prompt.started',
      status: 'running',
    });
    emitNearSigningConfirmationProgress(progressArgs, {
      requestId: 'near-passkey-progress',
      step: 2,
      phase: 'auth.passkey.prompt.succeeded',
      status: 'succeeded',
    });

    expect(events).toMatchObject([
      {
        phase: SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_STARTED,
        status: 'waiting_for_user',
        authMethod: 'passkey',
      },
      {
        phase: SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_SUCCEEDED,
        status: 'succeeded',
        authMethod: 'passkey',
      },
    ]);
  });

  test('reports Email OTP operation-step-up verification for shared sealed Ed25519 material', () => {
    const record = buildEmailOtpEd25519SealedSessionRecordFixture();
    if (!('providerSubjectId' in record.ed25519Restore)) {
      throw new Error('expected Email OTP Ed25519 restore material');
    }
    const signingAuthPlan = signingAuthPlanForNearMaterialRequirement({
      kind: 'email_otp',
      providerSubjectId: record.ed25519Restore.providerSubjectId,
    });
    const events: SigningFlowEvent[] = [];

    emitNearSigningConfirmationProgress(
      {
        onEvent: events.push.bind(events),
        nearAccountId: record.ed25519Restore.nearAccountId,
        signingAuthPlan,
      },
      {
        requestId: 'near-email-otp-progress',
        step: 2,
        phase: 'confirmation.complete',
        status: 'succeeded',
        message: 'Email OTP submitted',
      },
    );

    expect(events).toMatchObject([
      {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        authMethod: 'email_otp',
      },
    ]);
  });
});
