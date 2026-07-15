import type {
  EmailOtpAppSessionBinding,
  EmailOtpAppSessionJwtCache,
} from './appSessionJwtCache';

declare const cache: EmailOtpAppSessionJwtCache;
declare const binding: EmailOtpAppSessionBinding;

cache.remember(binding);

// @ts-expect-error Cache insertion requires a validated wallet/provider/token binding.
cache.remember({ walletId: binding.walletId, appSessionJwt: binding.appSessionJwt });
