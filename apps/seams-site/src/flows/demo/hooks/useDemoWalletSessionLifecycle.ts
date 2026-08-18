import { useEffect, useState } from 'react';
import { useSeams } from '@seams/wallet/react';

export type DemoWalletSessionLifecycleReadiness =
  | { readonly kind: 'initializing' }
  | { readonly kind: 'ready' }
  | { readonly kind: 'initialization_failed' };

export function useDemoWalletSessionLifecycle(): DemoWalletSessionLifecycleReadiness {
  const { seams } = useSeams();
  const [readiness, setReadiness] = useState<DemoWalletSessionLifecycleReadiness>({
    kind: 'initializing',
  });

  useEffect(() => {
    const lifecycle = { disposed: false };
    setReadiness({ kind: 'initializing' });
    void initializeWalletIframe({ seams, lifecycle, setReadiness });
    return function disposeWalletIframeInitialization(): void {
      lifecycle.disposed = true;
    };
  }, [seams]);

  return readiness;
}

async function initializeWalletIframe(args: {
  readonly seams: ReturnType<typeof useSeams>['seams'];
  readonly lifecycle: { disposed: boolean };
  readonly setReadiness: (readiness: DemoWalletSessionLifecycleReadiness) => void;
}): Promise<void> {
  try {
    await args.seams.initWalletIframe();
    if (!args.lifecycle.disposed) args.setReadiness({ kind: 'ready' });
  } catch (error: unknown) {
    if (!args.lifecycle.disposed) args.setReadiness({ kind: 'initialization_failed' });
    console.error('[demo] Wallet iframe initialization failed', error);
  }
}
