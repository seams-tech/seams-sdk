import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/wallet-iframe-handlers';
import {
  parseRegistrationActivationReadyPayload,
  parseRegistrationActivationStartedPayload,
  type ChildToParentEnvelope,
} from '@/SeamsWeb/walletIframe/shared/messages';

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
  registerPasskey: (options: any) => Promise<any>;
}) {
  return {
    getSeamsWeb: () =>
      ({
        registration: {
          registerPasskey: args.registerPasskey,
        },
      }) as any,
    post: (msg: ChildToParentEnvelope) => args.posts.push(msg),
    postProgress: () => undefined,
    isCancelled: () => false,
    respondIfCancelled: () => false,
  };
}

function makeActivationPrepareReq(override?: Partial<any>): any {
  return {
    type: 'PM_REGISTRATION_ACTIVATION_PREPARE',
    requestId: 'req-activation',
    payload: {
      activationId: 'activation-1',
      expiresAtMs: Date.now() + 60_000,
      wallet: { kind: 'provided', walletId: 'frost-fjord-rgcmpa' },
      options: {},
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
        expiresAtMs: 1_777_777_777_000,
      }),
    ).toEqual({
      activationId: 'activation-1',
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
      parseRegistrationActivationStartedPayload({ activationId: 'activation-1' }),
    ).toEqual({ activationId: 'activation-1' });
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
        registerPasskey: async (options) => {
          calls.push({ options });
          return await registration.promise;
        },
      }),
    );

    const preparePromise = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
      makeActivationPrepareReq({
        confirmationConfig: { uiMode: 'modal', behavior: 'requireClick', autoProceedDelay: 5 },
        presentation: {
          ...DEFAULT_ACTIVATION_PRESENTATION,
          iframeButtonStyle: {
            width: '100%',
            borderRadius: '999px',
            boxShadow: '0 10px 24px rgba(0, 0, 0, 0.18)',
          },
        },
      }),
    );
    await Promise.resolve();

    const button = document.querySelector<FakeElement>(
      '[data-seams-registration-activation-start="true"]',
    );
    expect(button).not.toBeNull();
    button!.click();
    button!.click();
    await Promise.resolve();

    expect(calls).toHaveLength(1);
    expect(calls[0]?.options).toEqual(
      expect.objectContaining({
        confirmationConfig: {
          uiMode: 'none',
          behavior: 'skipClick',
          autoProceedDelay: 0,
        },
        walletIframeActivation: expect.objectContaining({
          kind: 'wallet_iframe_registration_activation_v1',
          activationId: 'activation-1',
        }),
        wallet: { kind: 'provided', walletId: 'frost-fjord-rgcmpa' },
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

  test('activation cancel rejects pending prepare and removes the button', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        registerPasskey: async () => ({ success: true }),
      }),
    );

    const preparePromise = handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(makeActivationPrepareReq());
    await Promise.resolve();
    expect(document.querySelector('[data-seams-registration-activation-id]')).not.toBeNull();

    await handlers.PM_REGISTRATION_ACTIVATION_CANCEL!({
      type: 'PM_REGISTRATION_ACTIVATION_CANCEL',
      requestId: 'req-cancel',
      payload: {
        activationId: 'activation-1',
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

  test('expired activation requests do not render a button or start registration', async () => {
    const document = installDomShim();
    const posts: ChildToParentEnvelope[] = [];
    let registerCalls = 0;
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        registerPasskey: async () => {
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

  test('activation prepare rejects missing or invalid provided wallets', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        registerPasskey: async () => ({ success: true }),
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({ wallet: undefined }),
      ),
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

  test('activation presentation rejects unsupported CSS properties', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        registerPasskey: async () => ({ success: true }),
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            ...DEFAULT_ACTIVATION_PRESENTATION,
            iframeButtonStyle: {
              position: 'fixed',
            },
          },
        }),
      ),
    ).rejects.toThrow('unsupported CSS property position');
  });

  test('activation presentation rejects CSS URL values', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        registerPasskey: async () => ({ success: true }),
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            ...DEFAULT_ACTIVATION_PRESENTATION,
            iframeButtonStyle: {
              background: 'url(https://example.com/button.png)',
            },
          },
        }),
      ),
    ).rejects.toThrow('cannot use url(...)');
  });

  test('activation presentation rejects mixed branch fields at runtime boundary', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        registerPasskey: async () => ({ success: true }),
      }),
    );

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            ...DEFAULT_ACTIVATION_PRESENTATION,
            iframeVisualStyle: {
              borderRadius: '999px',
            },
          },
        }),
      ),
    ).rejects.toThrow('iframeVisualStyle is not allowed for outline_overlay');

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            ...DEFAULT_ACTIVATION_PRESENTATION,
            shadowPaddingPx: 12,
          },
        }),
      ),
    ).rejects.toThrow('shadowPaddingPx is not allowed for outline_overlay');

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            kind: 'iframe_button',
            label: 'Create passkey',
            busyLabel: 'Creating passkey...',
            accessibleLabel: 'Create passkey account',
            iframeVisualStyle: {
              borderRadius: '999px',
            },
            shadowPaddingPx: 12,
            iframeButtonStyle: {
              borderRadius: '999px',
            },
          },
        }),
      ),
    ).rejects.toThrow('iframeButtonStyle is not allowed for iframe_button');
  });

  test('iframe button presentation requires visual style and shadow padding', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const handlers = createWalletIframeHandlers(
      makeDeps({
        posts,
        registerPasskey: async () => ({ success: true }),
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
            shadowPaddingPx: 12,
          },
        }),
      ),
    ).rejects.toThrow('iframeVisualStyle is required');

    await expect(
      handlers.PM_REGISTRATION_ACTIVATION_PREPARE!(
        makeActivationPrepareReq({
          presentation: {
            kind: 'iframe_button',
            label: 'Create passkey',
            busyLabel: 'Creating passkey...',
            accessibleLabel: 'Create passkey account',
            iframeVisualStyle: {
              borderRadius: '999px',
            },
          },
        }),
      ),
    ).rejects.toThrow('shadowPaddingPx must be a non-negative number');
  });
});
