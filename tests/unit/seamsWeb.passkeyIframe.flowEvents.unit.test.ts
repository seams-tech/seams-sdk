import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from '../wallet-iframe/harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

const WALLET_STUB_PASSKEY_SCRIPT = String.raw`
  const accountId = 'alice.testnet';
  const walletId = 'frost-orchid-k7p9m2';

  const eventBase = (requestId, flow, phase, step, status, message, extra = {}) => ({
    version: 2,
    flow,
    step,
    phase,
    status,
    message,
    flowId: flow + ':passkey:test:' + requestId,
    requestId,
    accountId,
    authMethod: 'passkey',
    ...extra,
  });

  const postProgress = (requestId, payload) => {
    adoptedPort.postMessage({ type: 'PROGRESS', requestId, payload });
  };

  const postResult = (requestId, result) => {
    pendingRequests.delete(requestId);
    adoptedPort.postMessage({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
  };

  const originalAdoptPort = adoptPort;
  adoptPort = function patchedAdoptPort(port) {
    originalAdoptPort(port);
    if (!adoptedPort) return;

    const originalHandler = adoptedPort.onmessage;
    adoptedPort.onmessage = (event) => {
      originalHandler?.(event);
      const data = event.data || {};
      if (!data || typeof data !== 'object' || typeof data.requestId !== 'string') return;
      const requestId = data.requestId;

      if (data.type === 'PM_GET_WALLET_SESSION') {
        postResult(requestId, {
          login: {
            isLoggedIn: true,
            nearAccountId: accountId,
            publicKey: 'ed25519:alice',
            userData: null,
            authMethod: 'passkey',
          },
          signingSession: null,
          authMethod: 'passkey',
          retention: null,
        });
        return;
      }
      if (data.type === 'PM_PREFETCH_BLOCKHEIGHT') {
        postResult(requestId, null);
        return;
      }
      if (data.type === 'PM_GET_CONFIRMATION_CONFIG') {
        postResult(requestId, { behavior: 'requireClick', uiMode: 'modal' });
        return;
      }
      if (data.type === 'PM_GET_RECENT_UNLOCKS') {
        postResult(requestId, []);
        return;
      }

      if (data.type === 'PM_REGISTER_WALLET') {
        const signerSelection = data.payload && data.payload.signerSelection;
        [
          eventBase(requestId, 'registration', 'registration.started', 1, 'started', 'Starting registration'),
          eventBase(requestId, 'registration', 'registration.auth.passkey.create.started', 4, 'waiting_for_user', 'Create your passkey', {
            interaction: { kind: 'passkey_create', overlay: 'show' },
          }),
          eventBase(requestId, 'registration', 'registration.auth.passkey.create.succeeded', 4, 'succeeded', 'Passkey created', {
            interaction: { kind: 'passkey_create', overlay: 'hide' },
          }),
          eventBase(requestId, 'registration', 'registration.signer.ed25519.prepare.started', 5, 'running', 'Preparing NEAR signer'),
          eventBase(requestId, 'registration', 'registration.signer.ed25519.prepare.succeeded', 5, 'succeeded', 'NEAR signer ready'),
          eventBase(requestId, 'registration', 'registration.relay.bootstrap.started', 6, 'running', 'Creating wallet account'),
          eventBase(requestId, 'registration', 'registration.relay.bootstrap.succeeded', 6, 'succeeded', 'Wallet account created'),
          eventBase(requestId, 'registration', 'registration.account.verify.started', 7, 'running', 'Verifying wallet account'),
          eventBase(requestId, 'registration', 'registration.account.verify.succeeded', 7, 'succeeded', 'Wallet account verified'),
          eventBase(requestId, 'registration', 'registration.storage.persist.started', 8, 'running', 'Saving wallet metadata'),
          eventBase(requestId, 'registration', 'registration.storage.persist.succeeded', 8, 'succeeded', 'Wallet metadata saved'),
          eventBase(requestId, 'registration', 'registration.signer.ecdsa.provision.succeeded', 10, 'succeeded', 'EVM signer ready'),
          eventBase(requestId, 'registration', 'registration.completed', 11, 'succeeded', 'Registration complete'),
        ].forEach((payload) => postProgress(requestId, payload));
        postResult(requestId, {
          success: true,
          walletId,
          nearAccountId: accountId,
          loggedInNearAccountId: accountId,
          signerSelectionKind: signerSelection && (signerSelection.kind || signerSelection.mode),
          signerKinds: Array.isArray(signerSelection && signerSelection.signers)
            ? signerSelection.signers.map((signer) => signer.kind)
            : [],
        });
        return;
      }

      if (data.type === 'PM_UNLOCK') {
        [
          eventBase(requestId, 'unlock', 'unlock.started', 1, 'started', 'Unlocking wallet'),
          eventBase(requestId, 'unlock', 'unlock.account.lookup.started', 2, 'running', 'Finding wallet account'),
          eventBase(requestId, 'unlock', 'unlock.account.lookup.succeeded', 2, 'succeeded', 'Wallet account found'),
          eventBase(requestId, 'unlock', 'unlock.auth.passkey.challenge.started', 3, 'running', 'Preparing passkey check'),
          eventBase(requestId, 'unlock', 'unlock.auth.passkey.prompt.started', 3, 'waiting_for_user', 'Confirm with passkey', {
            interaction: { kind: 'passkey_assert', overlay: 'show' },
          }),
          eventBase(requestId, 'unlock', 'unlock.auth.passkey.prompt.succeeded', 3, 'succeeded', 'Passkey confirmed', {
            interaction: { kind: 'passkey_assert', overlay: 'hide' },
          }),
          eventBase(requestId, 'unlock', 'unlock.app_session.exchange.skipped', 4, 'skipped', 'App session skipped'),
          eventBase(requestId, 'unlock', 'unlock.session.ready', 6, 'succeeded', 'Wallet session ready'),
          eventBase(requestId, 'unlock', 'unlock.completed', 7, 'succeeded', 'Wallet unlocked'),
        ].forEach((payload) => postProgress(requestId, payload));
        postResult(requestId, {
          success: true,
          loggedInNearAccountId: accountId,
          nearAccountId: accountId,
          operationalPublicKey: 'ed25519:alice',
        });
      }
    };
  };
`;

test.describe('SeamsWeb passkey wallet iframe flow events', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: WALLET_STUB_PASSKEY_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
  });

  test('forwards passkey registration and unlock sequences through onEvent', async ({ page }) => {
    const result = await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;
        const pm = new SeamsWeb({
          relayer: { url: 'https://relay.example' },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        const registrationEvents: Array<Record<string, unknown>> = [];
        const unlockEvents: Array<Record<string, unknown>> = [];
        const withTimeout = async <T>(label: string, promise: Promise<T>): Promise<T> => {
          let timeoutId: number | undefined;
          const timeout = new Promise<never>((_, reject) => {
            timeoutId = window.setTimeout(() => reject(new Error(label + ' timed out')), 5000);
          });
          try {
            return await Promise.race([promise, timeout]);
          } finally {
            if (timeoutId !== undefined) window.clearTimeout(timeoutId);
          }
        };
        const captureEvent =
          (events: Array<Record<string, unknown>>) => (event: Record<string, unknown>) => {
            events.push({
              flow: event.flow,
              phase: event.phase,
              status: event.status,
              step: event.step,
              authMethod: event.authMethod,
              interaction: event.interaction,
            });
          };
        const registration = await withTimeout(
          'registration',
          pm.registration.registerPasskey({
            onEvent: captureEvent(registrationEvents),
          }),
        );
        const unlock = await withTimeout(
          'unlock',
          pm.auth.unlock('alice.testnet', {
            signingSession: { ttlMs: 0, remainingUses: 0 },
            onEvent: captureEvent(unlockEvents),
          }),
        );

        return {
          registrationSuccess: (registration as any).success,
          registrationSignerSetKind: (registration as any).signerSelectionKind,
          registrationSignerKinds: (registration as any).signerKinds,
          unlockSuccess: (unlock as any).success,
          registrationEventPhases: registrationEvents.map((event) => event.phase),
          registrationEventSteps: registrationEvents.map((event) => event.step),
          registrationEventFlows: [...new Set(registrationEvents.map((event) => event.flow))],
          registrationEventAuthMethods: [
            ...new Set(registrationEvents.map((event) => event.authMethod)),
          ],
          registrationInteractions: registrationEvents.map((event) => event.interaction ?? null),
          unlockEventPhases: unlockEvents.map((event) => event.phase),
          unlockEventSteps: unlockEvents.map((event) => event.step),
          unlockEventFlows: [...new Set(unlockEvents.map((event) => event.flow))],
          unlockEventAuthMethods: [...new Set(unlockEvents.map((event) => event.authMethod))],
          unlockInteractions: unlockEvents.map((event) => event.interaction ?? null),
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(result).toEqual({
      registrationSuccess: true,
      registrationSignerSetKind: 'signer_set',
      registrationSignerKinds: ['near_ed25519', 'evm_family_ecdsa'],
      unlockSuccess: true,
      registrationEventPhases: [
        'registration.started',
        'registration.auth.passkey.create.started',
        'registration.auth.passkey.create.succeeded',
        'registration.signer.ed25519.prepare.started',
        'registration.signer.ed25519.prepare.succeeded',
        'registration.relay.bootstrap.started',
        'registration.relay.bootstrap.succeeded',
        'registration.account.verify.started',
        'registration.account.verify.succeeded',
        'registration.storage.persist.started',
        'registration.storage.persist.succeeded',
        'registration.signer.ecdsa.provision.succeeded',
        'registration.completed',
      ],
      registrationEventSteps: [1, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 10, 11],
      registrationEventFlows: ['registration'],
      registrationEventAuthMethods: ['passkey'],
      registrationInteractions: [
        null,
        { kind: 'passkey_create', overlay: 'show' },
        { kind: 'passkey_create', overlay: 'hide' },
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
      ],
      unlockEventPhases: [
        'unlock.started',
        'unlock.account.lookup.started',
        'unlock.account.lookup.succeeded',
        'unlock.auth.passkey.challenge.started',
        'unlock.auth.passkey.prompt.started',
        'unlock.auth.passkey.prompt.succeeded',
        'unlock.app_session.exchange.skipped',
        'unlock.session.ready',
        'unlock.completed',
      ],
      unlockEventSteps: [1, 2, 2, 3, 3, 3, 4, 6, 7],
      unlockEventFlows: ['unlock'],
      unlockEventAuthMethods: ['passkey'],
      unlockInteractions: [
        null,
        null,
        null,
        null,
        { kind: 'passkey_assert', overlay: 'show' },
        { kind: 'passkey_assert', overlay: 'hide' },
        null,
        null,
        null,
      ],
    });
  });
});
