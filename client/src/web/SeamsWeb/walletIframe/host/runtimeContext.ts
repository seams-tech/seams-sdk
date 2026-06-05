import type {
  ChildToParentEnvelope,
  ParentToChildEnvelope,
  ParentToChildType,
  PreferencesChangedPayload,
  ProgressPayload,
} from '../shared/messages';
import { SeamsWeb } from '@/web/SeamsWeb';
import type { SeamsConfigsInput } from '@/core/types/seams';
import { setupLitElemMounter } from './lit-ui/iframe-lit-elem-mounter';
import {
  applyWalletConfig,
  createHostContext,
  ensureSeamsWeb,
  type HostContext,
} from './context';
import type { HandlerDeps, HandlerMap } from './handlers/types';

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

type HandlerFactory = (deps: HandlerDeps) => HandlerMap;

let runtimeContext: HostContext | null = null;
const handlerMaps = new Map<HandlerFactory, HandlerMap>();
let litMounterInstalled = false;

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

function installLitMounterOnce(ctx: HostContext, input: WalletHostRuntimeRequest): void {
  if (litMounterInstalled) return;
  litMounterInstalled = true;

  const ensureHostSeamsWeb = (): SeamsWeb => {
    const prev = ctx.seamsWeb;
    const pm = ensureSeamsWeb(ctx) as SeamsWeb;
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
    ensureSeamsWeb: ensureHostSeamsWeb,
    getSeamsWeb: () => ctx.seamsWeb,
    updateWalletConfigs: (patch) => {
      ctx.walletConfigs = {
        ...(ctx.walletConfigs || ({} as SeamsConfigsInput)),
        ...patch,
      } as SeamsConfigsInput;
      input.state.walletConfigs = ctx.walletConfigs;
    },
    postToParent: input.postToParent,
  });
}

function buildHandlerDeps(ctx: HostContext, input: WalletHostRuntimeRequest): HandlerDeps {
  const postProgress = (requestId: string | undefined, payload: ProgressPayload): void => {
    if (!requestId) return;
    input.post({ type: 'PROGRESS', requestId, payload });
  };

  const ensureHostSeamsWeb = (): SeamsWeb => ensureSeamsWeb(ctx) as SeamsWeb;

  return {
    getSeamsWeb: ensureHostSeamsWeb,
    post: input.post,
    postProgress,
    postToParent: input.postToParent,
    isCancelled: input.isCancelled,
    respondIfCancelled: input.respondIfCancelled,
  };
}

export async function handleWalletHostRuntimeRequestWithHandlers(
  input: WalletHostRuntimeRequest,
  createHandlers: HandlerFactory,
): Promise<void> {
  const ctx = syncRuntimeContext(input.state);
  installLitMounterOnce(ctx, input);

  let handlers = handlerMaps.get(createHandlers);
  if (!handlers) {
    handlers = createHandlers(buildHandlerDeps(ctx, input));
    handlerMaps.set(createHandlers, handlers);
  }

  const handler = handlers[input.req.type as ParentToChildType] as unknown as
    | ((r: ParentToChildEnvelope) => Promise<void>)
    | undefined;
  if (!handler) {
    throw new Error(`Unsupported wallet iframe request type: ${input.req.type}`);
  }
  await handler(input.req);
}
