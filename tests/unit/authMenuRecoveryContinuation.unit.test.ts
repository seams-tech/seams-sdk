import { expect, test } from '@playwright/test';
import { AuthMenuSession } from '@/SeamsWeb/walletIframe/host/auth-menu/session';
import type {
  HostedRecoveryEmailOtpVerified,
  HostedRecoveryCredentialCreated,
  HostedRecoveryFinalizationOperation,
  HostedRecoveryGoogleVerified,
  HostedRecoveryPort,
  HostedRecoveryPrepared,
} from '@/SeamsWeb/walletIframe/host/recovery-port';
import {
  buildHostedAuthMenuOpenRequest,
  hostedAuthMenuSessionIdFromBoundary,
} from '@/SeamsWeb/walletIframe/shared/messages';
import { walletIframeRequestIdFromBoundary } from '@/core/types/walletIframeIdentity';
import type { AppearanceConfig } from '@/core/types/seams';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { WalletRecoveryTargetV1 } from '@shared/wallet-recovery/walletRecoveryTarget';

type AuthMenuSessionArgs = ConstructorParameters<typeof AuthMenuSession>[0];

const APPEARANCE = {
  theme: { id: 'default', mode: 'dark', colors: {} },
  palette: 'default',
} as const satisfies AppearanceConfig;

const PASSKEY_TARGET = {
  kind: 'passkey',
  rpId: 'wallet.example.test',
} as const satisfies WalletRecoveryTargetV1;

const AUTH_MENU_REQUEST_ID = walletIframeRequestIdFromBoundary('auth-menu-recovery-request');

class SuccessfulRecoveryPort implements HostedRecoveryPort {
  readonly calls: string[] = [];
  readonly targets: WalletRecoveryTargetV1[] = [];
  readonly walletId = walletIdFromString('recovered-wallet.test');

  targetFor(kind: WalletRecoveryTargetV1['kind']): WalletRecoveryTargetV1 {
    return kind === 'passkey' ? PASSKEY_TARGET : { kind, googleProvider: 'google' };
  }

  async prepare(input: Parameters<HostedRecoveryPort['prepare']>[0]) {
    this.calls.push(`prepare:${input.recoveryCode}`);
    this.targets.push(input.target);
    return {
      kind: 'hosted_recovery_prepared' as const,
      recoveryOperationId: 'recovery-operation-1',
      walletId: this.walletId,
      target: input.target,
    };
  }

  async createPasskey(operation: HostedRecoveryPrepared) {
    this.calls.push(`create:${operation.recoveryOperationId}`);
    return {
      kind: 'hosted_recovery_credential_created' as const,
      recoveryOperationId: operation.recoveryOperationId,
      walletId: operation.walletId,
      target: operation.target,
    };
  }

  async verifyGoogle(operation: HostedRecoveryPrepared, idToken: string) {
    this.calls.push(`verify-google:${operation.recoveryOperationId}:${idToken}`);
    return {
      kind: 'hosted_recovery_google_verified' as const,
      recoveryOperationId: operation.recoveryOperationId,
      walletId: operation.walletId,
      target: { kind: 'google_email_otp' as const, googleProvider: 'google' as const },
      challengeId: 'recovery-email-challenge-1',
      delivery: { kind: 'provider' as const, status: 'sent' as const, emailHint: 'r***@test' },
      expiresAtMs: Date.now() + 60_000,
    };
  }

  async verifyEmailOtp(operation: HostedRecoveryGoogleVerified) {
    this.calls.push(`verify-email:${operation.recoveryOperationId}`);
    return {
      kind: 'hosted_recovery_email_otp_verified' as const,
      recoveryOperationId: operation.recoveryOperationId,
      walletId: operation.walletId,
      target: operation.target,
      challengeId: operation.challengeId,
    };
  }

  async finalize(operation: HostedRecoveryFinalizationOperation) {
    this.calls.push(`finalize:${operation.recoveryOperationId}`);
    return { kind: 'ready_for_sign_in' as const, walletId: operation.walletId };
  }

  async cancel(
    operation:
      | HostedRecoveryPrepared
      | HostedRecoveryCredentialCreated
      | HostedRecoveryGoogleVerified
      | HostedRecoveryEmailOtpVerified,
  ): Promise<void> {
    this.calls.push(`cancel:${operation.recoveryOperationId}`);
  }
}

class RetryablePasskeyCreationRecoveryPort extends SuccessfulRecoveryPort {
  override async createPasskey(operation: HostedRecoveryPrepared) {
    this.calls.push(`create:${operation.recoveryOperationId}`);
    return { kind: 'transport_uncertain' as const };
  }
}

class RetryableFinalizationRecoveryPort extends SuccessfulRecoveryPort {
  private shouldFail = true;

  override async finalize(operation: HostedRecoveryFinalizationOperation) {
    this.calls.push(`finalize:${operation.recoveryOperationId}`);
    if (this.shouldFail) {
      this.shouldFail = false;
      return { kind: 'transport_uncertain' as const };
    }
    return { kind: 'ready_for_sign_in' as const, walletId: operation.walletId };
  }
}

class RefusingRecoveryPort implements HostedRecoveryPort {
  targetFor(kind: WalletRecoveryTargetV1['kind']): WalletRecoveryTargetV1 {
    return kind === 'passkey' ? PASSKEY_TARGET : { kind, googleProvider: 'google' };
  }

  async prepare(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async createPasskey(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async verifyGoogle(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async verifyEmailOtp(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async finalize(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async cancel(): Promise<void> {}
}

class ConsumedRecoveryPort extends RefusingRecoveryPort {
  override async prepare(): Promise<{ readonly kind: 'consumed' }> {
    return { kind: 'consumed' };
  }
}

class DeferredFinalizationRecoveryPort extends SuccessfulRecoveryPort {
  private resolveFinalization:
    | ((value: { kind: 'ready_for_sign_in'; walletId: SuccessfulRecoveryPort['walletId'] }) => void)
    | null = null;

  override async finalize(operation: HostedRecoveryCredentialCreated) {
    this.calls.push(`finalize:${operation.recoveryOperationId}`);
    return await new Promise<{
      kind: 'ready_for_sign_in';
      walletId: SuccessfulRecoveryPort['walletId'];
    }>((resolve) => {
      this.resolveFinalization = resolve;
    });
  }

  completeFinalization(): void {
    const resolve = this.resolveFinalization;
    if (!resolve) throw new Error('recovery finalization has not started');
    this.resolveFinalization = null;
    resolve({ kind: 'ready_for_sign_in', walletId: this.walletId });
  }
}

function sessionWithRecovery(args: {
  recoveryPort: HostedRecoveryPort;
  prepareRecoveredLogin: AuthMenuSessionArgs['prepareRecoveredLogin'];
  initialMode?: 'login' | 'register';
}): AuthMenuSession {
  const sessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-recovery-session');
  if (!sessionId) throw new Error('auth-menu recovery session fixture is invalid');
  return new AuthMenuSession({
    request: buildHostedAuthMenuOpenRequest({
      authMenuSessionId: sessionId,
      initialMode: args.initialMode ?? 'login',
      enabledExternalProviders: ['google'],
    }),
    requestId: AUTH_MENU_REQUEST_ID,
    appearance: APPEARANCE,
    hostname: 'wallet.example.test',
    beginGoogleEmailOtp: rejectGoogleFlow,
    startDeviceLinking: rejectDeviceLinking,
    cancelDeviceLinking: resolveCancellation,
    recoveryPort: args.recoveryPort,
    prepareRecoveredLogin: args.prepareRecoveredLogin,
    sendToParent: ignoreParentMessage,
  });
}

async function rejectGoogleFlow(): Promise<never> {
  throw new Error('Google flow is outside this recovery fixture');
}

async function rejectDeviceLinking(): Promise<never> {
  throw new Error('Device linking is outside this recovery fixture');
}

async function resolveCancellation(): Promise<void> {}

function ignoreParentMessage(): void {}

function invoke(session: AuthMenuSession, method: string, ...args: unknown[]): void {
  Reflect.apply(Reflect.get(session, method), session, args);
}

test.describe('hosted auth-menu recovery continuation', () => {
  test('opens recovery on a cold device whose menu starts in registration mode', () => {
    const session = sessionWithRecovery({
      recoveryPort: new SuccessfulRecoveryPort(),
      prepareRecoveredLogin: rejectRecoveredLogin,
      initialMode: 'register',
    });

    invoke(session, 'openRecovery');

    expect(session.state.kind).toBe('recovery');
    if (session.state.kind !== 'recovery') throw new Error('recovery state was not opened');
    expect(session.state.returnState.viewModel.mode).toBe('register');
    invoke(session, 'back');
    expect(session.state.kind).toBe('preparing');
    if (session.state.kind !== 'preparing') throw new Error('registration state was not restored');
    expect(session.state.viewModel.kind).toBe('passkey');
    if (session.state.viewModel.kind !== 'passkey')
      throw new Error('passkey state was not restored');
    expect(session.state.viewModel.mode).toBe('register');
    session.cleanup();
  });

  test('starts passkey creation immediately after recovery preparation', async () => {
    const recoveryPort = new SuccessfulRecoveryPort();
    const loginWalletIds: string[] = [];
    const prepareRecoveredLogin: AuthMenuSessionArgs['prepareRecoveredLogin'] = async (
      walletId,
    ) => {
      loginWalletIds.push(walletId);
      throw new Error('Stop after proving the normal-login continuation');
    };
    const session = sessionWithRecovery({ recoveryPort, prepareRecoveredLogin });

    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery');
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('sign_in_ready');

    expect(recoveryPort.calls).toEqual([
      'prepare:ABCD-EFGH',
      'create:recovery-operation-1',
      'finalize:recovery-operation-1',
    ]);
    expect(loginWalletIds).toEqual(['recovered-wallet.test']);
    if (session.state.kind !== 'recovery') throw new Error('recovery state was lost');
    expect(session.state.viewModel.subtitle).toBe(
      'Your account is ready, login again with your Passkey',
    );
    expect(session.state.viewModel.status).toEqual({
      kind: 'recoverable',
      reason: 'error',
      message: 'Your account was recovered. Prepare sign in again to continue.',
    });
    session.cleanup();
  });

  test('starts Google recovery immediately and replaces the recovery form with its OTP step', async () => {
    const recoveryPort = new SuccessfulRecoveryPort();
    const session = sessionWithRecovery({
      recoveryPort,
      prepareRecoveredLogin: rejectRecoveredLogin,
    });

    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery', 'google_email_otp');

    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('google_external_auth');
    expect(recoveryPort.targets).toEqual([{ kind: 'google_email_otp', googleProvider: 'google' }]);
    if (session.state.kind !== 'recovery' || session.state.stage !== 'google_external_auth') {
      throw new Error('Google recovery did not start');
    }
    const accepted = session.acceptExternalAuthResolution({
      kind: 'hosted_auth_menu_external_auth_resolution_v1',
      authMenuSessionId: session.state.request.authMenuSessionId,
      externalAuthRequestId: session.state.request.externalAuthRequestId,
      requestId: AUTH_MENU_REQUEST_ID,
      evidence: { kind: 'google_id_token', idToken: 'google-id-token-1' },
    });
    expect(accepted).toBe(true);
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('email_code_required');
    expect(recoveryPort.calls).toEqual([
      'prepare:ABCD-EFGH',
      'verify-google:recovery-operation-1:google-id-token-1',
    ]);
    if (session.state.kind !== 'recovery' || session.state.stage !== 'email_code_required') {
      throw new Error('Recovery OTP form did not replace the recovery form');
    }
    expect(session.state.viewModel.emailHint).toBe('r***@test');
    session.cleanup();
  });

  test('submits Google recovery automatically when the sixth OTP digit is entered', async () => {
    const recoveryPort = new SuccessfulRecoveryPort();
    const session = sessionWithRecovery({
      recoveryPort,
      prepareRecoveredLogin: rejectRecoveredLogin,
    });

    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery', 'google_email_otp');
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('google_external_auth');
    if (session.state.kind !== 'recovery' || session.state.stage !== 'google_external_auth') {
      throw new Error('Google recovery did not start');
    }
    session.acceptExternalAuthResolution({
      kind: 'hosted_auth_menu_external_auth_resolution_v1',
      authMenuSessionId: session.state.request.authMenuSessionId,
      externalAuthRequestId: session.state.request.externalAuthRequestId,
      requestId: AUTH_MENU_REQUEST_ID,
      evidence: { kind: 'google_id_token', idToken: 'google-id-token-1' },
    });
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('email_code_required');

    invoke(session, 'changeRecoveryGoogleOtpCode', '123456');

    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('sign_in_ready');
    if (session.state.kind !== 'recovery' || session.state.stage !== 'sign_in_ready') {
      throw new Error('Google recovery did not reach sign-in');
    }
    expect(session.state.viewModel.subtitle).toBe('Your Google account is ready to sign in.');
    expect(recoveryPort.calls).toEqual([
      'prepare:ABCD-EFGH',
      'verify-google:recovery-operation-1:google-id-token-1',
      'verify-email:recovery-operation-1',
      'finalize:recovery-operation-1',
    ]);
    session.cleanup();
  });

  test('cancels a prepared operation when Back leaves a passkey retry', async () => {
    const recoveryPort = new RetryablePasskeyCreationRecoveryPort();
    const session = sessionWithRecovery({
      recoveryPort,
      prepareRecoveredLogin: rejectRecoveredLogin,
    });
    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery');
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('passkey_ready');
    if (session.state.kind !== 'recovery') throw new Error('recovery state was lost');
    expect(session.state.viewModel.status).toEqual({
      kind: 'recoverable',
      reason: 'error',
      message: 'A passkey couldn’t be created. Try again.',
    });

    invoke(session, 'back');

    await expect.poll(() => recoveryPort.calls.at(-1)).toBe('cancel:recovery-operation-1');
    expect(session.state.kind).not.toBe('recovery');
    session.cleanup();
  });

  test('keeps irreversible finalization alive when Back or Close is requested', async () => {
    const recoveryPort = new DeferredFinalizationRecoveryPort();
    const session = sessionWithRecovery({
      recoveryPort,
      prepareRecoveredLogin: rejectRecoveredLogin,
    });
    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery');
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('finalizing');
    await expect.poll(() => recoveryPort.calls.at(-1)).toBe('finalize:recovery-operation-1');

    invoke(session, 'back');
    session.cancel('close_button');

    expect(session.state.kind === 'recovery' && session.state.stage).toBe('finalizing');
    expect(recoveryPort.calls).not.toContain('cancel:recovery-operation-1');

    recoveryPort.completeFinalization();
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('sign_in_ready');
    session.cleanup();
  });

  test('keeps finalization retryable without blaming the recovery code', async () => {
    const recoveryPort = new RetryableFinalizationRecoveryPort();
    const session = sessionWithRecovery({
      recoveryPort,
      prepareRecoveredLogin: rejectRecoveredLogin,
    });
    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery');

    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.viewModel.status)
      .toEqual({
        kind: 'recoverable',
        reason: 'error',
        message: 'Recovery couldn’t be completed. Try again.',
      });
    expect(recoveryPort.calls).toEqual([
      'prepare:ABCD-EFGH',
      'create:recovery-operation-1',
      'finalize:recovery-operation-1',
    ]);

    invoke(session, 'createRecoveryPasskey');
    await expect.poll(() => recoveryPort.calls.length).toBe(4);
    expect(recoveryPort.calls.at(-1)).toBe('finalize:recovery-operation-1');
    session.cleanup();
  });

  test('maps code refusal to one generic recovery message', async () => {
    const session = sessionWithRecovery({
      recoveryPort: new RefusingRecoveryPort(),
      prepareRecoveredLogin: rejectRecoveredLogin,
    });
    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'USED-CODE');
    invoke(session, 'prepareRecovery');

    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('enter_code');
    if (session.state.kind !== 'recovery') throw new Error('recovery state was lost');
    expect(session.state.viewModel.status).toEqual({
      kind: 'recoverable',
      reason: 'error',
      message: 'That recovery code can’t be used. Check the code and try again.',
    });
    session.cleanup();
  });

  test('identifies a recovery code this client already consumed', async () => {
    const session = sessionWithRecovery({
      recoveryPort: new ConsumedRecoveryPort(),
      prepareRecoveredLogin: rejectRecoveredLogin,
    });
    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryCode', 'USED-CODE');
    invoke(session, 'prepareRecovery');

    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('enter_code');
    if (session.state.kind !== 'recovery') throw new Error('recovery state was lost');
    expect(session.state.viewModel.status).toEqual({
      kind: 'recoverable',
      reason: 'error',
      message: 'That recovery code has already been used. Use another code.',
    });
    session.cleanup();
  });
});

async function rejectRecoveredLogin(): Promise<never> {
  throw new Error('Recovered login is outside this refusal fixture');
}
