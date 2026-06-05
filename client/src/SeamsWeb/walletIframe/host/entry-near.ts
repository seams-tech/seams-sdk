import { initWalletIFrame, type WalletHostRuntimeKind } from './index';

const NEAR_HOST_RUNTIME_KINDS = new Set<WalletHostRuntimeKind>([
  'auth',
  'near',
  'export',
  'device_link',
  'recovery',
  'preferences',
]);

initWalletIFrame({ supportedRuntimeRouteKinds: NEAR_HOST_RUNTIME_KINDS });

