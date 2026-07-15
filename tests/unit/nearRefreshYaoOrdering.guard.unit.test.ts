import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const nearTransactionSourcePath =
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts';
const nearSigningSourcePath = 'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts';

function readNearTransactionSigningFunction(): string {
  const source = fs.readFileSync(path.join(repoRoot, nearTransactionSourcePath), 'utf8');
  const functionStart = source.indexOf(
    'export async function runNearTransactionWithActionsSigning(',
  );
  const nextFunctionStart = source.indexOf(
    '\nfunction validateAndPrepareSigningContext(',
    functionStart,
  );

  expect(functionStart).toBeGreaterThanOrEqual(0);
  expect(nextFunctionStart).toBeGreaterThan(functionStart);
  return source.slice(functionStart, nextFunctionStart);
}

function requireMarkerIndex(source: string, marker: string): number {
  const markerIndex = source.indexOf(marker);
  expect(markerIndex, `missing NEAR signing marker: ${marker}`).toBeGreaterThanOrEqual(0);
  return markerIndex;
}

function readNearSigningSource(): string {
  return fs.readFileSync(path.join(repoRoot, nearSigningSourcePath), 'utf8');
}

test.describe('page-refresh NEAR Yao capability recovery ordering guard', () => {
  test('transaction cancellation cannot invoke deferred capability resolution', () => {
    const source = readNearTransactionSigningFunction();
    const confirmationIndex = requireMarkerIndex(
      source,
      'const confirmation = await runSigningConfirmationCommand({',
    );
    const capabilityRecoveryIndex = requireMarkerIndex(
      source,
      'await resolveNearEd25519YaoCapabilitySource(yaoCapabilitySource)',
    );

    expect(source.slice(0, confirmationIndex)).not.toContain(
      'resolveNearEd25519YaoCapabilitySource(yaoCapabilitySource)',
    );
    expect(capabilityRecoveryIndex).toBeGreaterThan(confirmationIndex);
  });

  test('review approval completes before deferred capability resolution starts', () => {
    const source = readNearTransactionSigningFunction();
    const confirmationIndex = requireMarkerIndex(
      source,
      'const confirmation = await runSigningConfirmationCommand({',
    );
    const approvalIndex = requireMarkerIndex(
      source,
      'phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED',
    );
    const payloadPreparationIndex = requireMarkerIndex(
      source,
      'const preparedPayload = await runSharedNearTransactionCommand({',
    );
    const capabilityRecoveryIndex = requireMarkerIndex(
      source,
      'await resolveNearEd25519YaoCapabilitySource(yaoCapabilitySource)',
    );

    expect(approvalIndex).toBeGreaterThan(confirmationIndex);
    expect(payloadPreparationIndex).toBeGreaterThan(approvalIndex);
    expect(capabilityRecoveryIndex).toBeGreaterThan(payloadPreparationIndex);
  });

  test('durable nonce recovery is awaited after approval and before payload preparation', () => {
    const source = readNearTransactionSigningFunction();
    const approvalIndex = requireMarkerIndex(
      source,
      'phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED',
    );
    const nonceRecoveryIndex = requireMarkerIndex(
      source,
      'await ctx.nonceCoordinator.recoverDurableLeases({',
    );
    const payloadPreparationIndex = requireMarkerIndex(
      source,
      'const preparedPayload = await runSharedNearTransactionCommand({',
    );

    expect(nonceRecoveryIndex).toBeGreaterThan(approvalIndex);
    expect(payloadPreparationIndex).toBeGreaterThan(nonceRecoveryIndex);
  });

  test('capability recovery invalidates the pre-recovery budget admission', () => {
    const source = readNearTransactionSigningFunction();
    const capabilityRecoveryIndex = requireMarkerIndex(
      source,
      'await resolveNearEd25519YaoCapabilitySource(yaoCapabilitySource)',
    );
    const budgetInvalidationIndex = requireMarkerIndex(
      source,
      'nearEd25519YaoResolutionRequiresBudgetReadmission(yaoCapabilitySource)',
    );
    const budgetReadmissionIndex = requireMarkerIndex(
      source,
      'await admitSelectedNearTransactionLaneBudget(buildBudgetSigningLane())',
    );

    expect(budgetInvalidationIndex).toBeGreaterThan(capabilityRecoveryIndex);
    expect(budgetReadmissionIndex).toBeGreaterThan(budgetInvalidationIndex);
  });

  test('reauth-required Email OTP lanes defer Yao activation to the confirmed reconnect', () => {
    const source = readNearSigningSource();
    const sourceBuilderIndex = requireMarkerIndex(
      source,
      'function nearEd25519YaoCapabilitySource(args:',
    );
    const nextFunctionIndex = requireMarkerIndex(
      source.slice(sourceBuilderIndex),
      '\nasync function emailOtpNearEd25519LaneRequiresFreshAuth(',
    );
    const sourceBuilder = source.slice(sourceBuilderIndex, sourceBuilderIndex + nextFunctionIndex);

    expect(sourceBuilder).toContain("case 'email_otp':");
    expect(sourceBuilder).toContain("return { kind: 'email_otp_reconnect' };");
    expect(sourceBuilder).not.toContain('active Ed25519 Yao capability is unavailable');
  });

  test('a refreshed Email OTP lane silently restores a valid durable grant before requesting OTP', () => {
    const source = readNearSigningSource();
    const reconnectPolicyIndex = requireMarkerIndex(
      source,
      'async function emailOtpNearEd25519LaneRequiresFreshAuth(args:',
    );
    const nextFunctionIndex = requireMarkerIndex(
      source.slice(reconnectPolicyIndex),
      '\nfunction createAdHocNearSigningOperationId(',
    );
    const reconnectPolicy = source.slice(
      reconnectPolicyIndex,
      reconnectPolicyIndex + nextFunctionIndex,
    );

    expect(reconnectPolicy).toContain("case 'passkey':");
    expect(reconnectPolicy).toContain("case 'email_otp':");
    expect(reconnectPolicy).toContain(
      'await args.deps.recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning({',
    );
    expect(reconnectPolicy).toContain("case 'recovered':");
    expect(reconnectPolicy).toContain('return false;');
    expect(reconnectPolicy).toContain("case 'reauth_required':");
    expect(reconnectPolicy).toContain('return true;');
    expect(reconnectPolicy).not.toContain('requestEmailOtpEd25519SigningChallenge');
    expect(source).toContain('emailOtpNearEd25519LaneRequiresFreshAuth({');
    expect(source).toContain('forceFreshAuth,');
  });
});
