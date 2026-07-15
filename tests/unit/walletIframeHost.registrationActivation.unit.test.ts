import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/wallet-iframe-handlers';
import {
  parseRegistrationActivationReadyPayload,
  parseRegistrationActivationStartedPayload,
  type ChildToParentEnvelope,
} from '@/SeamsWeb/walletIframe/shared/messages';
import { webAuthnPromptCoordinator } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import { activatePreparedIframePasskeyRegistration, SeamsWeb } from '@/SeamsWeb/SeamsWeb';

type Deferred<T> = {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason?: unknown): void;
};

class FakeElement {
  readonly style: Record<string, string> = {};
  readonly children: FakeElement[] = [];
  readonly listeners = new Map<string, Array<() => void>>();
  readonly attributes = new Map<string, string>();
  parent: FakeElement | null = null;
  textContent = '';
  type = '';
  disabled = false;
  removed = false;

  constructor(readonly tagName: string) {}

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }

  append(...children: FakeElement[]): void {
    for (const child of children) {
      this.appendChild(child);
    }
  }

  appendChild(child: FakeElement): FakeElement {
    child.parent = this;
    this.children.push(child);
    return child;
  }

  addEventListener(type: string, listener: () => void): void {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  click(): void {
    if (this.disabled) return;
    for (const listener of this.listeners.get('click') || []) {
      listener();
    }
  }

  remove(): void {
    this.removed = true;
    if (!this.parent) return;
    const index = this.parent.children.indexOf(this);
    if (index >= 0) this.parent.children.splice(index, 1);
    this.parent = null;
  }
}

class FakeDocument {
  readonly elements: FakeElement[] = [];
  readonly body = this.createElement('body');

  createElement(tagName: string): FakeElement {
    const element = new FakeElement(tagName);
    this.elements.push(element);
    return element;
  }

  querySelector<T = FakeElement>(selector: string): T | null {
    return (this.querySelectorAll(selector)[0] as T | undefined) ?? null;
  }

  querySelectorAll(selector: string): FakeElement[] {
    return this.elements.filter(
      (element) => !element.removed && matchesSelector(element, selector),
    );
  }
}

function matchesSelector(element: FakeElement, selector: string): boolean {
  if (selector === '[data-seams-registration-activation-id]') {
    return element.getAttribute('data-seams-registration-activation-id') !== null;
  }
  if (selector === '[data-seams-registration-activation-start="true"]') {
    return element.getAttribute('data-seams-registration-activation-start') === 'true';
  }
  return false;
}

function installDomShim(): FakeDocument {
  const document = new FakeDocument();
  (globalThis as { document?: unknown }).document = document;
  (globalThis as { window?: unknown }).window = {
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
  };
  return document;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const DEFAULT_ACTIVATION_PRESENTATION = {
  kind: 'outline_overlay',
  label: 'Create passkey',
  busyLabel: 'Creating passkey...',
  accessibleLabel: 'Create passkey account',
} as const;

function makeDeps(args: {
  posts: ChildToParentEnvelope[];
  continuePrepared: (activated: any) => Promise<any>;
  onDisposePrepared?: () => void;
}) {
  const prepared = {
    kind: 'prepared_iframe_passkey_registration_v1',
    registration: {},
    precompute: { handle: {} },
    walletId: 'frost-fjord-rgcmpa',
    rpId: 'wallet.example.localhost',
    signerSlot: 1,
    challengeB64u: 'challenge',
    expiresAtMs: Date.now() + 60_000,
  };
  return {
    getSeamsWeb: () =>
      ({
        prepareIframePasskeyRegistration: async ({ expiresAtMs }: { expiresAtMs: number }) => ({
          ...prepared,
          expiresAtMs,
        }),
        continuePreparedIframePasskeyRegistration: (activated: any) => {
          webAuthnPromptCoordinator.releaseReservation(activated.reservation);
          const result = args.continuePrepared(activated);
          return result;
        },
        disposePreparedIframePasskeyRegistration: () => args.onDisposePrepared?.(),
      }) as any,
    post: (msg: ChildToParentEnvelope) => args.posts.push(msg),
    postProgress: () => undefined,
    isCancelled: () => false,
    respondIfCancelled: () => false,
  };
}

function makeActivationCancelReq(
  args: {
    activationId?: string;
    surfaceId?: string;
    activationRequestId?: string;
    cancelRequestId?: string;
  } = {},
): any {
  return {
    type: 'PM_REGISTRATION_ACTIVATION_CANCEL',
    requestId: args.cancelRequestId ?? 'req-cancel',
    payload: {
      activationId: args.activationId ?? 'activation-1',
      surfaceId: args.surfaceId ?? 'surface-1',
      requestId: args.activationRequestId ?? 'req-activation',
      reason: 'disposed',
    },
  };
}

function makeActivationPrepareReq(override?: Partial<any>): any {
  return {
    type: 'PM_REGISTRATION_ACTIVATION_PREPARE',
    requestId: 'req-activation',
    payload: {
      activationId: 'activation-1',
      surfaceId: 'surface-1',
      requestId: 'req-activation',
      expiresAtMs: Date.now() + 60_000,
      wallet: { kind: 'provided', walletId: 'frost-fjord-rgcmpa' },
      presentation: DEFAULT_ACTIVATION_PRESENTATION,
      ...override,
    },
  };
}

test.describe('wallet iframe host registration activation', () => {
  test.beforeEach(() => {
    installDomShim();
  });

  test('registration activation push payload parsers reject malformed states', () => {
    expect(
      parseRegistrationActivationReadyPayload({
        activationId: 'activation-1',
        surfaceId: 'surface-1',
        requestId: 'request-1',
        expiresAtMs: 1_777_777_777_000,
      }),
    ).toEqual({
      activationId: 'activation-1',
      surfaceId: 'surface-1',
      requestId: 'request-1',
      expiresAtMs: 1_777_777_777_000,
    });
    expect(parseRegistrationActivationReadyPayload({ activationId: 'activation-1' })).toBeNull();
    expect(
      parseRegistrationActivationReadyPayload({
        activationId: 'activation-1',
        expiresAtMs: 'not-a-number',
      }),
    ).toBeNull();
    expect(
      parseRegistrationActivationReadyPayload({
        activationId: 'activation-1',
        expiresAtMs: 1_777_777_777_000.5,
      }),
    ).toBeNull();
    expect(
      parseRegistrationActivationReadyPayload({
        activationId: 123,
        expiresAtMs: 1_777_777_777_000,
      }),
    ).toBeNull();
    expect(
      parseRegistrationActivationStartedPayload({
        activationId: 'activation-1',
        surfaceId: 'surface-1',
        requestId: 'request-1',
      }),
    ).toEqual({
      activationId: 'activation-1',
      surfaceId: 'surface-1',
      requestId: 'request-1',
    });
    expect(parseRegistrationActivationStartedPayload({ activationId: 123 })).toBeNull();
    expect(parseRegistrationActivationStartedPayload({ activationId: '' })).toBeNull();
    expect(parseRegistrationActivationStartedPayload({})).toBeNull();
  });

  test('activation button mints the iframe proof and ignores duplicate clicks', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    const registration = createDeferred<any>();
    const calls: Array<{ options: any }> = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async (activated) => {
          calls.push({ options: activated });
          return await registration.promise;
        },
      }),
    );

    const preparePromise = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(makeActivationPrepareReq());
    await new Promise((resolve) => setTimeout(resolve, 0));

    const button = document.querySelector<FakeElement>(
      '[data-seams-registration-activation-start="true"]',
    );
    expect(button).not.toBeNull();
    const readyMessage = posts.find(
      (message) => message.type === 'PM_REGISTRATION_ACTIVATION_READY',
    );
    expect(readyMessage?.payload).toEqual({
      activationId: 'activation-1',
      surfaceId: 'surface-1',
      requestId: 'req-activation',
      expiresAtMs: expect.any(Number),
    });
    button!.click();
    button!.click();
    await Promise.resolve();

    expect(calls).toHaveLength(1);
    expect(calls[0]?.options).toEqual(
      expect.objectContaining({
        kind: 'activated_prepared_iframe_passkey_registration_v1',
        activation: expect.objectContaining({
          identity: {
            activationId: 'activation-1',
            surfaceId: 'surface-1',
            requestId: 'req-activation',
          },
          activatedAtMs: expect.any(Number),
        }),
      }),
    );
    expect(posts.some((msg) => msg.type === 'PM_REGISTRATION_ACTIVATION_READY')).toBe(true);
    expect(posts.some((msg) => msg.type === 'PM_REGISTRATION_ACTIVATION_STARTED')).toBe(true);

    registration.resolve({ success: true });
    await preparePromise;

    expect(posts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'PM_RESULT',
          requestId: 'req-activation',
          payload: expect.objectContaining({ ok: true }),
        }),
      ]),
    );
    expect(document.querySelector('[data-seams-registration-activation-id]')).toBeNull();
  });

  test('prepared Yao continuation starts reserved WebAuthn before its first await', async () => {
    const identity = {
      activationId: 'activation-sync-webauthn',
      surfaceId: 'surface-sync-webauthn',
      requestId: 'request-sync-webauthn',
    } as any;
    const cancellation = { kind: 'abort_signal', signal: new AbortController().signal } as const;
    const reservation = {
      kind: 'reserved_registration_webauthn_prompt_v1',
      reservationId: 'reservation-sync-webauthn',
      owner: { kind: 'registration_activation', identity },
      expiresAtMs: Date.now() + 60_000,
    } as any;
    const activated = activatePreparedIframePasskeyRegistration({
      prepared: {
        kind: 'prepared_iframe_passkey_registration_v1',
        registration: {
          wallet: { kind: 'provided', walletId: 'wallet-sync-webauthn' },
          authMethod: { kind: 'passkey', rpId: 'wallet.example.test' },
          signerSelection: {
            kind: 'signer_set',
            signers: [
              {
                kind: 'near_ed25519',
                accountProvisioning: { kind: 'implicit_account' },
                signerSlot: 3,
                participantIds: [11, 29],
                derivationVersion: 1,
              },
            ],
          },
          options: {},
        },
        precompute: {
          kind: 'prepared_passkey_registration_precompute_v1',
          handle: {},
          walletId: 'wallet-sync-webauthn',
          registrationIntentDigestB64u: 'intent-digest-sync-webauthn',
        },
        walletId: 'wallet-sync-webauthn',
        rpId: 'wallet.example.test',
        signerSlot: 3,
        challengeB64u: 'intent-digest-sync-webauthn',
        expiresAtMs: Date.now() + 60_000,
      } as any,
      identity,
      reservation,
      cancellation,
      activatedAtMs: Date.now(),
    });
    expect(Object.isFrozen(activated)).toBe(true);
    expect(Object.isFrozen(activated.activation)).toBe(true);
    expect(Object.isFrozen(activated.activation.identity)).toBe(true);
    expect(Object.isFrozen(activated.reservation)).toBe(true);
    expect(Object.isFrozen(activated.reservation.owner)).toBe(true);
    expect(Object.isFrozen(activated.cancellation)).toBe(true);
    const callOrder: string[] = [];
    const fakeSeamsWeb = {
      configs: { webauthn: { authenticatorOptions: {} } },
      signingEngine: {
        startPreparedPasskeyRegistrationCredential: () => {
          callOrder.push('webauthn');
          return Promise.resolve({
            id: 'credential-sync-webauthn',
            rawId: 'credential-sync-webauthn',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              attestationObject: 'attestation-object',
              transports: ['internal'],
            },
            clientExtensionResults: {
              prf: { results: { first: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } },
            },
          });
        },
      },
      getContext: () => {
        callOrder.push('registration-continuation');
        return {};
      },
    };

    const resultPromise = Reflect.apply(
      SeamsWeb.prototype.continuePreparedIframePasskeyRegistration,
      fakeSeamsWeb,
      [activated],
    ) as Promise<{ success: boolean; error?: string }>;

    expect(callOrder).toEqual(['webauthn', 'registration-continuation']);
    await expect(resultPromise).resolves.toMatchObject({
      success: false,
      error: expect.stringContaining('Invalid prepared passkey registration precompute'),
    });
  });

  test('cancelling after activation aborts the started registration operation', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    const registration = createDeferred<any>();
    let operationSignal: AbortSignal | null = null;
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async (activated) => {
          operationSignal = activated.cancellation.signal;
          return await registration.promise;
        },
      }),
    );

    const preparePromise = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(makeActivationPrepareReq());
    await new Promise((resolve) => setTimeout(resolve, 0));
    const button = document.querySelector<FakeElement>(
      '[data-seams-registration-activation-start="true"]',
    );
    button!.click();
    await Promise.resolve();

    expect(operationSignal).not.toBeNull();
    expect(operationSignal!.aborted).toBe(false);
    expect(document.querySelector('[data-seams-registration-activation-id]')).toBeNull();

    await handlers.PM_REGISTRATION_ACTIVATION_CANCEL!({
      type: 'PM_REGISTRATION_ACTIVATION_CANCEL',
      requestId: 'req-cancel-started',
      payload: {
        activationId: 'activation-1',
        surfaceId: 'surface-1',
        requestId: 'req-activation',
        reason: 'disposed',
      },
    } as any);

    expect(operationSignal!.aborted).toBe(true);
    await expect(preparePromise).rejects.toThrow('Registration activation cancelled');
    registration.reject(new Error('registration aborted'));
  });

  test('activation cancel rejects pending prepare and removes the button', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => ({ success: true }),
      }),
    );

    const preparePromise = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(makeActivationPrepareReq());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(document.querySelector('[data-seams-registration-activation-id]')).not.toBeNull();

    await handlers.PM_REGISTRATION_ACTIVATION_CANCEL!({
      type: 'PM_REGISTRATION_ACTIVATION_CANCEL',
      requestId: 'req-cancel',
      payload: {
        activationId: 'activation-1',
        surfaceId: 'surface-1',
        requestId: 'req-activation',
        reason: 'disposed',
      },
    } as any);

    await expect(preparePromise).rejects.toThrow('Registration activation cancelled');
    expect(document.querySelector('[data-seams-registration-activation-id]')).toBeNull();
    expect(posts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'PM_RESULT',
          requestId: 'req-cancel',
          payload: { ok: true },
        }),
      ]),
    );
  });

  test('replacement cancels only the old activation and releases each ready record once', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    let disposeCalls = 0;
    let releaseCalls = 0;
    const originalReleaseReservation =
      webAuthnPromptCoordinator.releaseReservation.bind(webAuthnPromptCoordinator);
    webAuthnPromptCoordinator.releaseReservation = (reservation) => {
      releaseCalls += 1;
      originalReleaseReservation(reservation);
    };
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => ({ success: true }),
        onDisposePrepared: () => {
          disposeCalls += 1;
        },
      }),
    );

    try {
      const firstPrepare = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(makeActivationPrepareReq());
      const firstCancellation = expect(firstPrepare).rejects.toThrow(
        'Registration activation cancelled',
      );
      await expect
        .poll(() =>
          posts.some(
            (message) =>
              message.type === 'PM_REGISTRATION_ACTIVATION_READY' &&
              message.payload.requestId === 'req-activation',
          ),
        )
        .toBe(true);

      const secondRequest = makeActivationPrepareReq({
        surfaceId: 'surface-2',
        requestId: 'req-activation-2',
      });
      secondRequest.requestId = 'req-activation-2';
      const secondPrepare = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(secondRequest);
      const secondCancellation = expect(secondPrepare).rejects.toThrow(
        'Registration activation cancelled',
      );

      await firstCancellation;
      await expect
        .poll(() =>
          posts.some(
            (message) =>
              message.type === 'PM_REGISTRATION_ACTIVATION_READY' &&
              message.payload.requestId === 'req-activation-2',
          ),
        )
        .toBe(true);
      expect(document.querySelector('[data-seams-registration-activation-id]')).not.toBeNull();
      expect(releaseCalls).toBe(1);
      expect(disposeCalls).toBe(1);

      await handlers.PM_REGISTRATION_ACTIVATION_CANCEL!(
        makeActivationCancelReq({
          surfaceId: 'surface-2',
          activationRequestId: 'req-activation-2',
        }),
      );
      await secondCancellation;
      expect(releaseCalls).toBe(2);
      expect(disposeCalls).toBe(2);
      expect(document.querySelector('[data-seams-registration-activation-id]')).toBeNull();
    } finally {
      webAuthnPromptCoordinator.releaseReservation = originalReleaseReservation;
    }
  });

  test('busy coordinator delays ready and grants the reservation before activation', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const runningOperation = createDeferred<void>();
    const running = webAuthnPromptCoordinator.runImmediate({
      owner: {
        kind: 'wallet_request',
        requestId: 'blocking-authentication',
        operation: 'authentication',
      },
      operation: () => runningOperation.promise,
    });
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => ({ success: true }),
      }),
    );
    const prepare = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(makeActivationPrepareReq());
    const cancellation = expect(prepare).rejects.toThrow('Registration activation cancelled');

    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(posts.some((message) => message.type === 'PM_REGISTRATION_ACTIVATION_READY')).toBe(
      false,
    );

    runningOperation.resolve();
    await running;
    await expect
      .poll(() => posts.some((message) => message.type === 'PM_REGISTRATION_ACTIVATION_READY'))
      .toBe(true);

    await handlers.PM_REGISTRATION_ACTIVATION_CANCEL!(makeActivationCancelReq());
    await cancellation;
  });

  test('activation cancel during async button definition rejects pending prepare', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    const definition = createDeferred<void>();
    (globalThis as { customElements?: unknown }).customElements = {
      get: () => ({}),
      whenDefined: () => definition.promise,
    };
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => ({ success: true }),
      }),
    );

    try {
      const preparePromise = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq(),
      );
      await new Promise((resolve) => setTimeout(resolve, 0));

      await handlers.PM_REGISTRATION_ACTIVATION_CANCEL!({
        type: 'PM_REGISTRATION_ACTIVATION_CANCEL',
        requestId: 'req-cancel',
        payload: {
          activationId: 'activation-1',
          surfaceId: 'surface-1',
          requestId: 'req-activation',
          reason: 'disposed',
        },
      } as any);
      definition.resolve();

      await expect(preparePromise).rejects.toThrow('Registration activation cancelled');
      expect(document.querySelector('[data-seams-registration-activation-id]')).toBeNull();
      expect(posts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: 'PM_RESULT',
            requestId: 'req-cancel',
            payload: { ok: true },
          }),
        ]),
      );
    } finally {
      delete (globalThis as { customElements?: unknown }).customElements;
    }
  });

  test('expired activation requests do not render a button or start registration', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    let registerCalls = 0;
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => {
          registerCalls += 1;
          return { success: true };
        },
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({ expiresAtMs: Date.now() - 1 }),
      ),
    ).rejects.toThrow('Registration activation expired');

    expect(registerCalls).toBe(0);
    expect(posts).toEqual([]);
    expect(document.querySelector('[data-seams-registration-activation-id]')).toBeNull();
  });

  test('prepared activation expires before WebAuthn when no click occurs', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    let continuationCalls = 0;
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => {
          continuationCalls += 1;
          return { success: true };
        },
      }),
    );

    const prepare = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
      makeActivationPrepareReq({ expiresAtMs: Date.now() + 30 }),
    );
    const expiration = expect(prepare).rejects.toThrow('Registration activation expired');
    await new Promise((resolve) => setTimeout(resolve, 60));

    await expiration;
    expect(continuationCalls).toBe(0);
    expect(document.querySelector('[data-seams-registration-activation-id]')).toBeNull();
  });

  test('activation prepare rejects missing or invalid provided wallets', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => ({ success: true }),
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(makeActivationPrepareReq({ wallet: undefined })),
    ).rejects.toThrow('Registration activation requires a provided wallet');

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({ wallet: { kind: 'server_allocated' } }),
      ),
    ).rejects.toThrow('Registration activation requires a provided wallet');

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({ wallet: { kind: 'provided', walletId: '' } }),
      ),
    ).rejects.toThrow();
  });

  test('activation presentation rejects wallet-origin visual style fields', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => ({ success: true }),
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            ...DEFAULT_ACTIVATION_PRESENTATION,
            iframeButtonStyle: {
              borderRadius: '999px',
            },
          },
        }),
      ),
    ).rejects.toThrow('iframeButtonStyle is not allowed');
  });

  test('activation presentation rejects the internal iframe button mode', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        continuePrepared: async () => ({ success: true }),
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            kind: 'iframe_button',
            label: 'Create passkey',
            busyLabel: 'Creating passkey...',
            accessibleLabel: 'Create passkey account',
          },
        }),
      ),
    ).rejects.toThrow('Invalid registration activation presentation kind');
  });
});
