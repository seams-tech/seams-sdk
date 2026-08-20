import { expect, test } from '@playwright/test';
import { AuthMenuSession } from '@/SeamsWeb/walletIframe/host/auth-menu/session';
import type {
  HostedRecoveryCredentialCreated,
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

type AuthMenuSessionArgs = ConstructorParameters<typeof AuthMenuSession>[0];

const APPEARANCE = {
  theme: { id: 'default', mode: 'dark', colors: {} },
  palette: 'default',
} as const satisfies AppearanceConfig;

class SuccessfulRecoveryPort implements HostedRecoveryPort {
  readonly calls: string[] = [];
  readonly walletId = walletIdFromString('recovered-wallet.test');

  async prepare(input: Parameters<HostedRecoveryPort['prepare']>[0]) {
    this.calls.push(`prepare:${input.walletId}:${input.recoveryCode}`);
    return {
      kind: 'hosted_recovery_prepared' as const,
      recoveryOperationId: 'recovery-operation-1',
      walletId: this.walletId,
    };
  }

  async createPasskey(operation: HostedRecoveryPrepared) {
    this.calls.push(`create:${operation.recoveryOperationId}`);
    return {
      kind: 'hosted_recovery_credential_created' as const,
      recoveryOperationId: operation.recoveryOperationId,
      walletId: operation.walletId,
    };
  }

  async finalize(operation: HostedRecoveryCredentialCreated) {
    this.calls.push(`finalize:${operation.recoveryOperationId}`);
    return { kind: 'ready_for_sign_in' as const, walletId: operation.walletId };
  }

  async cancel(operation: HostedRecoveryPrepared | HostedRecoveryCredentialCreated): Promise<void> {
    this.calls.push(`cancel:${operation.recoveryOperationId}`);
  }
}

class RefusingRecoveryPort implements HostedRecoveryPort {
  async prepare(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async createPasskey(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async finalize(): Promise<{ readonly kind: 'refused' }> {
    return { kind: 'refused' };
  }

  async cancel(): Promise<void> {}
}

function sessionWithRecovery(args: {
  recoveryPort: HostedRecoveryPort;
  prepareRecoveredLogin: AuthMenuSessionArgs['prepareRecoveredLogin'];
}): AuthMenuSession {
  const sessionId = hostedAuthMenuSessionIdFromBoundary('auth-menu-recovery-session');
  if (!sessionId) throw new Error('auth-menu recovery session fixture is invalid');
  return new AuthMenuSession({
    request: buildHostedAuthMenuOpenRequest({
      authMenuSessionId: sessionId,
      initialMode: 'login',
      enabledExternalProviders: [],
    }),
    requestId: walletIframeRequestIdFromBoundary('auth-menu-recovery-request'),
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
  test('prepares one code, creates one passkey, then targets normal login for that wallet', async () => {
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
    invoke(session, 'changeRecoveryWalletId', 'recovered-wallet.test');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery');
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('passkey_ready');
    if (session.state.kind !== 'recovery') throw new Error('recovery state was lost');
    expect(session.state.viewModel.recoveryCode).toBe('');

    invoke(session, 'createRecoveryPasskey');
    expect(recoveryPort.calls).toEqual([
      'prepare:recovered-wallet.test:ABCD-EFGH',
      'create:recovery-operation-1',
    ]);
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('sign_in_ready');

    expect(recoveryPort.calls).toEqual([
      'prepare:recovered-wallet.test:ABCD-EFGH',
      'create:recovery-operation-1',
      'finalize:recovery-operation-1',
    ]);
    expect(loginWalletIds).toEqual(['recovered-wallet.test']);
    if (session.state.kind !== 'recovery') throw new Error('recovery state was lost');
    expect(session.state.viewModel.status).toEqual({
      kind: 'recoverable',
      reason: 'error',
      message: 'Your account was recovered. Prepare sign in again to continue.',
    });
    session.cleanup();
  });

  test('cancels a prepared operation when Back leaves recovery', async () => {
    const recoveryPort = new SuccessfulRecoveryPort();
    const session = sessionWithRecovery({
      recoveryPort,
      prepareRecoveredLogin: rejectRecoveredLogin,
    });
    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryWalletId', 'recovered-wallet.test');
    invoke(session, 'changeRecoveryCode', 'ABCD-EFGH');
    invoke(session, 'prepareRecovery');
    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('passkey_ready');

    invoke(session, 'back');

    await expect.poll(() => recoveryPort.calls.at(-1)).toBe('cancel:recovery-operation-1');
    expect(session.state.kind).not.toBe('recovery');
    session.cleanup();
  });

  test('maps code refusal to one generic recovery message', async () => {
    const session = sessionWithRecovery({
      recoveryPort: new RefusingRecoveryPort(),
      prepareRecoveredLogin: rejectRecoveredLogin,
    });
    invoke(session, 'openRecovery');
    invoke(session, 'changeRecoveryWalletId', 'recovered-wallet.test');
    invoke(session, 'changeRecoveryCode', 'USED-CODE');
    invoke(session, 'prepareRecovery');

    await expect
      .poll(() => session.state.kind === 'recovery' && session.state.stage)
      .toBe('enter_code');
    if (session.state.kind !== 'recovery') throw new Error('recovery state was lost');
    expect(session.state.viewModel.status).toEqual({
      kind: 'recoverable',
      reason: 'error',
      message: 'That recovery code can’t be used. Check the wallet ID and code, then try again.',
    });
    session.cleanup();
  });
});

async function rejectRecoveredLogin(): Promise<never> {
  throw new Error('Recovered login is outside this refusal fixture');
}
