import type { PasskeyFixture } from './fixtures';
import type { TestUtils } from './index';
import { printLog } from './logging';
import { ActionType } from '@/core/types/actions';
import type { Page } from '@playwright/test';

export interface WalletIframeAutoConfirmDiagnostics {
  attempts: number;
  clicked: boolean;
  firstIframeAttachedMs?: number;
  firstFrameResolvedMs?: number;
  firstButtonVisibleMs?: number;
  firstClickDispatchMs?: number;
  firstClickDurationMs?: number;
  totalMs?: number;
}

function recordAutoConfirmMark(
  diagnostics: WalletIframeAutoConfirmDiagnostics | undefined,
  startedAtMs: number | undefined,
  key: keyof Omit<WalletIframeAutoConfirmDiagnostics, 'attempts' | 'clicked'>,
  valueMs?: number,
): void {
  if (!diagnostics || startedAtMs == null) return;
  if (diagnostics[key] != null) return;
  diagnostics[key] = Math.max(0, Math.round(valueMs ?? Date.now() - startedAtMs));
}

export async function clickWalletIframeConfirm(
  page: Page,
  opts?: {
    timeoutMs?: number;
    diagnostics?: WalletIframeAutoConfirmDiagnostics;
    diagnosticsStartedAtMs?: number;
  },
): Promise<boolean> {
  const timeoutMs = Math.max(50, Math.floor(opts?.timeoutMs ?? 15_000));
  if (opts?.diagnostics) {
    opts.diagnostics.attempts += 1;
  }
  try {
    const iframeEl = page.locator('iframe[allow*="publickey-credentials-get"]').last();
    const attached = await iframeEl
      .waitFor({ state: 'attached', timeout: timeoutMs })
      .then(() => true)
      .catch(() => false);
    if (!attached) return false;
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstIframeAttachedMs');
    const frame = await iframeEl.contentFrame();
    if (!frame) return false;
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstFrameResolvedMs');

    const confirmBtn = frame
      .locator(
        [
          '[data-seams-registration-activation-start="true"]',
          '#w3a-confirm-portal button.btn-confirm',
          '#w3a-confirm-portal button.confirm',
        ].join(', '),
      )
      .first();
    await confirmBtn.waitFor({ state: 'visible', timeout: timeoutMs });
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstButtonVisibleMs');
    const clickStartedAtMs = Date.now();
    await confirmBtn.click({ timeout: timeoutMs });
    if (opts?.diagnostics) {
      opts.diagnostics.clicked = true;
    }
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstClickDispatchMs');
    recordAutoConfirmMark(
      opts?.diagnostics,
      opts?.diagnosticsStartedAtMs,
      'firstClickDurationMs',
      Date.now() - clickStartedAtMs,
    );
    return true;
  } catch {
    return false;
  }
}

export async function autoConfirmWalletIframeUntil<T>(
  page: Page,
  task: Promise<T>,
  opts?: {
    timeoutMs?: number;
    intervalMs?: number;
    retryDelayMs?: number;
    stopAfterClick?: boolean;
    diagnostics?: WalletIframeAutoConfirmDiagnostics;
  },
): Promise<T> {
  const timeoutMs = Math.max(250, Math.floor(opts?.timeoutMs ?? 55_000));
  const intervalMs = Math.max(50, Math.floor(opts?.intervalMs ?? 250));
  const retryDelayMs = Math.max(0, Math.floor(opts?.retryDelayMs ?? intervalMs));
  const stopAfterClick = opts?.stopAfterClick === true;

  let done = false;
  const startedAtMs = Date.now();
  const diagnostics = opts?.diagnostics;
  if (diagnostics) {
    diagnostics.attempts = 0;
    diagnostics.clicked = false;
  }

  const loop = (async () => {
    const deadline = Date.now() + timeoutMs;
    while (!done && Date.now() < deadline) {
      let clicked = false;
      try {
        clicked = await clickWalletIframeConfirm(page, {
          timeoutMs: Math.min(500, intervalMs),
          diagnostics,
          diagnosticsStartedAtMs: startedAtMs,
        });
      } catch {}
      if (clicked && stopAfterClick) return;
      try {
        if (retryDelayMs > 0) {
          await page.waitForTimeout(retryDelayMs);
        }
      } catch {}
    }
  })();

  try {
    return await task;
  } finally {
    done = true;
    if (diagnostics) {
      diagnostics.totalMs = Math.max(0, Math.round(Date.now() - startedAtMs));
    }
    await loop.catch(() => undefined);
  }
}

export interface RegistrationFlowOptions {
  accountId?: string;
  confirmVariant?: 'none' | 'skipClick';
}

export interface RegistrationFlowResult {
  success: boolean;
  accountId: string;
  events: any[];
  error?: string;
  skippedDueToExisting?: boolean;
  raw?: any;
}

export async function registerPasskey(
  passkey: PasskeyFixture,
  options: RegistrationFlowOptions = {},
): Promise<RegistrationFlowResult> {
  await passkey.setup();

  const accountId =
    options.accountId ??
    (await passkey.withTestUtils(() => {
      const utils = (window as any).testUtils as TestUtils;
      return utils.generateTestAccountId();
    }));

  printLog('flow', `starting registration for ${accountId}`, { step: 'register' });

  const registrationPromise = passkey.withTestUtils(
    (args) => {
      const utils = (window as any).testUtils as TestUtils;
      const events: any[] = [];

      const confirmVariant = args.confirmVariant ?? 'none';
      const overrides = (utils.confirmOverrides ?? {}) as Record<string, any>;
      const defaultConfirm = { uiMode: 'none', behavior: 'skipClick', autoProceedDelay: 0 };
      const confirmConfig = overrides[confirmVariant] ?? overrides.none ?? defaultConfirm;

      try {
        console.log(`[flow:register] invoking registerPasskey for ${args.accountId}`);
        return utils.seams.registration
          .registerPasskey({
            signerOptions: {
              tempo: {
                enabled: false,
                signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
              },
              evm: {
                enabled: false,
                signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
              },
            },
            onEvent: (event: any) => {
              events.push(event);
              console.log(`[flow:register]   -> ${event.phase} | ${event.message}`);
            },
            onError: (error: any) => {
              console.error(`[flow:register] ! ${error}`);
            },
            confirmationConfig: confirmConfig,
          })
          .then((result: any) => {
            const resolvedAccountId = String(
              result?.nearAccountId || result?.resolvedAccount?.accountId || args.accountId,
            );
            const response: RegistrationFlowResult = {
              success: !!result.success,
              accountId: resolvedAccountId,
              events,
              raw: result,
              error: result?.error,
              skippedDueToExisting: false,
            };

            if (
              !response.success &&
              typeof response.error === 'string' &&
              response.error.includes('already exists')
            ) {
              response.skippedDueToExisting = true;
              response.success = true;
            }

            return response;
          });
      } catch (error: any) {
        console.error(`[flow:register] error: ${error?.message || error}`);
        const fallback: RegistrationFlowResult = {
          success: false,
          accountId: args.accountId,
          events,
          error: error?.message || String(error),
          skippedDueToExisting: false,
        };
        return fallback;
      }
    },
    { accountId, confirmVariant: options.confirmVariant ?? 'none' },
  );

  // Registration in a cross-origin wallet iframe requires user activation.
  // confirmTxFlow enforces requireClick; keep clicking while the browser-side
  // registration promise is pending (more reliable than a one-shot click).
  const registrationResult = await autoConfirmWalletIframeUntil(passkey.page, registrationPromise, {
    timeoutMs: 90_000,
    intervalMs: 250,
  });

  if (registrationResult.skippedDueToExisting) {
    printLog('flow', `registration skipped because ${accountId} already exists`, {
      step: 'register',
      indent: 1,
    });
  } else {
    printLog(
      'flow',
      `registration ${registrationResult.success ? 'succeeded' : 'failed'} for ${accountId}`,
      {
        step: 'register',
        indent: 1,
      },
    );
  }

  return registrationResult;
}

export interface LoginFlowOptions {
  accountId: string;
}

export interface LoginFlowResult {
  success: boolean;
  accountId: string;
  events: any[];
  error?: string;
  raw?: any;
}

export async function unlock(
  passkey: PasskeyFixture,
  options: LoginFlowOptions,
): Promise<LoginFlowResult> {
  await passkey.setup();

  const accountId = options.accountId;
  printLog('flow', `starting login for ${accountId}`, { step: 'login' });

  const loginPromise = passkey.withTestUtils(
    (args) => {
      const utils = (window as any).testUtils as TestUtils;
      const toAccountId = (window as any).toAccountId ?? ((id: string) => id);
      const events: any[] = [];

      try {
        console.log(`[flow:login] invoking unlock for ${args.accountId}`);
        return utils.seams.auth
          .unlock(toAccountId(args.accountId), {
            onEvent: (event: any) => {
              events.push(event);
              console.log(`[flow:login]   -> ${event.phase} | ${event.message}`);
            },
            onError: (error: any) => {
              console.error(`[flow:login] ! ${error}`);
            },
          })
          .then((result: any) => ({
            success: !!result.success,
            accountId: args.accountId,
            events,
            error: result?.error,
            raw: result,
          }));
      } catch (error: any) {
        console.error(`[flow:login] error: ${error?.message || error}`);
        return {
          success: false,
          accountId: args.accountId,
          events,
          error: error?.message || String(error),
        };
      }
    },
    { accountId },
  );

  const loginResult = await autoConfirmWalletIframeUntil(passkey.page, loginPromise, {
    timeoutMs: 60_000,
    intervalMs: 250,
  });

  printLog('flow', `login ${loginResult.success ? 'succeeded' : 'failed'} for ${accountId}`, {
    step: 'login',
    indent: 1,
  });

  return loginResult;
}

export interface TransferFlowOptions {
  accountId: string;
  receiverId: string;
  amountYocto: string;
  actionType?: ActionType.Transfer;
}

export interface TransferFlowResult {
  success: boolean;
  events: any[];
  error?: string;
  raw?: any;
}

export async function executeTransfer(
  passkey: PasskeyFixture,
  options: TransferFlowOptions,
): Promise<TransferFlowResult> {
  await passkey.setup();

  const actionType = options.actionType ?? ActionType.Transfer;

  printLog('flow', `initiating transfer ${options.accountId} → ${options.receiverId}`, {
    step: 'transfer',
  });

  const resultPromise = passkey.withTestUtils(
    (args) => {
      const utils = (window as any).testUtils as TestUtils;
      const toAccountId = (window as any).toAccountId ?? ((id: string) => id);
      const events: any[] = [];

      try {
        console.log(`[flow:transfer] executing action for ${args.accountId}`);
        return utils.seams.near
          .executeAction({
            walletSession: {
              walletId: args.accountId,
              walletSessionUserId: args.accountId,
            } as any,
            nearAccount: { kind: 'named', accountId: toAccountId(args.accountId) },
            receiverId: args.receiverId,
            actionArgs: {
              type: args.actionType ?? 'Transfer',
              amount: args.amountYocto,
            },
            options: {
              onEvent: (event: any) => {
                events.push(event);
                console.log(`[flow:transfer]   -> ${event.phase} | ${event.message}`);
              },
              onError: (error: any) => {
                console.error(`[flow:transfer] ! ${error}`);
              },
            },
          })
          .then((result: any) => ({
            success: !!result.success,
            events,
            error: result?.error,
            raw: result,
          }));
      } catch (error: any) {
        console.error(`[flow:transfer] error: ${error?.message || error}`);
        return {
          success: false,
          events,
          error: error?.message || String(error),
        };
      }
    },
    { ...options, actionType },
  );

  const result = await autoConfirmWalletIframeUntil(passkey.page, resultPromise, {
    timeoutMs: 60_000,
    intervalMs: 250,
  });

  printLog('flow', `transfer ${result.success ? 'succeeded' : 'failed'}`, {
    step: 'transfer',
    indent: 1,
  });

  return result;
}
