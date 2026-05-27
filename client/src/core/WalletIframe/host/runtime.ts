import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
  ParentToChildType,
  PreferencesChangedPayload,
  ProgressPayload,
} from '../shared/messages';
import { SeamsPasskey } from '../../SeamsPasskey';
import type { SeamsConfigsInput } from '../../types/seams';
import { setupLitElemMounter } from './lit-ui/iframe-lit-elem-mounter';
import { createWalletIframeHandlers } from './wallet-iframe-handlers';
import {
  applyWalletConfig,
  createHostContext,
  ensurePasskeyManager,
  type HostContext,
} from './context';

export type WalletHostRuntimeState = {
  parentOrigin: string | null;
  port: MessagePort | null;
  walletConfigs: SeamsConfigsInput | null;
};

export type WalletHostRuntimeRequest = {
  state: WalletHostRuntimeState;
  req: ParentToChildEnvelope;
  post(msg: ChildToParentEnvelope): void;
  postToParent(msg: unknown): void;
  isCancelled(requestId: string | undefined): boolean;
  respondIfCancelled(requestId: string | undefined): boolean;
};

let runtimeContext: HostContext | null = null;
let handlers:
  | Partial<{
      [K in ParentToChildType]: (
        req: Extract<ParentToChildEnvelope, { type: K }>,
      ) => Promise<void>;
    }>
  | null = null;

function syncRuntimeContext(state: WalletHostRuntimeState): HostContext {
  if (!runtimeContext) {
    runtimeContext = createHostContext();
  }
  runtimeContext.parentOrigin = state.parentOrigin;
  runtimeContext.port = state.port;
  if (state.walletConfigs) {
    applyWalletConfig(runtimeContext, state.walletConfigs);
    state.walletConfigs = runtimeContext.walletConfigs;
  }
  return runtimeContext;
}

function ensureRuntime(input: WalletHostRuntimeRequest) {
  const ctx = syncRuntimeContext(input.state);
  if (handlers) return handlers;

  const postProgress = (requestId: string | undefined, payload: ProgressPayload): void => {
    if (!requestId) return;
    input.post({ type: 'PROGRESS', requestId, payload });
  };

  const ensureSeamsPasskey = (): SeamsPasskey => {
    const prev = ctx.seamsPasskey;
    const pm = ensurePasskeyManager(ctx) as SeamsPasskey;
    if (prev !== pm) {
      const up = pm.preferences;
      ctx.prefsUnsubscribe?.();
      const emitPreferencesChanged = () => {
        const id = String(up.getCurrentWalletId?.() || '').trim();
        input.post({
          type: 'PREFERENCES_CHANGED',
          payload: {
            walletId: id ? id : null,
            confirmationConfig: up.getConfirmationConfig(),
            updatedAt: Date.now(),
          } satisfies PreferencesChangedPayload,
        });
      };
      const unsubCfg = up.onConfirmationConfigChange?.(() => emitPreferencesChanged()) || null;
      const unsubCurrentWallet = up.onCurrentWalletChange?.(() => emitPreferencesChanged()) || null;
      ctx.prefsUnsubscribe = () => {
        try {
          unsubCfg?.();
        } catch {}
        try {
          unsubCurrentWallet?.();
        } catch {}
      };
      Promise.resolve()
        .then(() => emitPreferencesChanged())
        .catch(() => {});
    }
    return pm;
  };

  setupLitElemMounter({
    ensureSeamsPasskey,
    getSeamsPasskey: () => ctx.seamsPasskey,
    updateWalletConfigs: (patch) => {
      ctx.walletConfigs = {
        ...(ctx.walletConfigs || ({} as SeamsConfigsInput)),
        ...patch,
      } as SeamsConfigsInput;
      input.state.walletConfigs = ctx.walletConfigs;
    },
    postToParent: input.postToParent,
  });

  handlers = createWalletIframeHandlers({
    getSeamsPasskey: ensureSeamsPasskey,
    post: input.post,
    postProgress,
    postToParent: input.postToParent,
    isCancelled: input.isCancelled,
    respondIfCancelled: input.respondIfCancelled,
  });
  return handlers;
}

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  const activeHandlers = ensureRuntime(input);
  const handler = activeHandlers[input.req.type as ParentToChildType] as unknown as
    | ((r: ParentToChildEnvelope) => Promise<void>)
    | undefined;
  if (!handler) {
    throw new Error(`Unsupported wallet iframe request type: ${input.req.type}`);
  }
  await handler(input.req);
}
