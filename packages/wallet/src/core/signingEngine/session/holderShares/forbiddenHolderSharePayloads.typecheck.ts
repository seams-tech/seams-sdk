import type { OpenHolderShareHandle } from './holderShareHandle';

type AppVisibleHolderShareMessage = {
  kind: 'app_visible_holder_share_message';
  handle: OpenHolderShareHandle;
  holderShareBytes?: never;
  passkeyPrfOutputB64u?: never;
  recoveryCodePlaintext?: never;
};

declare const handle: OpenHolderShareHandle;

const validMessage: AppVisibleHolderShareMessage = {
  kind: 'app_visible_holder_share_message',
  handle,
};
void validMessage;

const invalidHolderShareMessage: AppVisibleHolderShareMessage = {
  kind: 'app_visible_holder_share_message',
  handle,
  // @ts-expect-error App-visible messages must not carry holder-share bytes.
  holderShareBytes: 'raw-share',
};
void invalidHolderShareMessage;

const invalidPrfMessage: AppVisibleHolderShareMessage = {
  kind: 'app_visible_holder_share_message',
  handle,
  // @ts-expect-error App-visible messages must not carry passkey PRF outputs.
  passkeyPrfOutputB64u: 'prf',
};
void invalidPrfMessage;

const invalidRecoveryCodeMessage: AppVisibleHolderShareMessage = {
  kind: 'app_visible_holder_share_message',
  handle,
  // @ts-expect-error App-visible messages must not carry recovery-code plaintext.
  recoveryCodePlaintext: 'AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH',
};
void invalidRecoveryCodeMessage;

export {};
