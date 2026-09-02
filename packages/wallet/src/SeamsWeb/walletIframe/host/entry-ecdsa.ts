import { initWalletIFrame, type WalletHostRuntimeKind } from './index';

const ECDSA_HOST_RUNTIME_KINDS = new Set<WalletHostRuntimeKind>([
  'auth',
  'ecdsa',
  'email_otp',
  'export',
  'recovery',
  'preferences',
]);

initWalletIFrame({ supportedRuntimeRouteKinds: ECDSA_HOST_RUNTIME_KINDS });

