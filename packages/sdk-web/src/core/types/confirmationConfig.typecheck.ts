import { normalizeConfirmationConfig } from './confirmationConfig';
import type { NormalizedConfirmationConfig } from './confirmationConfig.types';

const visibleRequireClick: NormalizedConfirmationConfig = {
  kind: 'interactive',
  uiMode: 'modal',
  behavior: 'requireClick',
};

const visibleAutoProceed: NormalizedConfirmationConfig = {
  kind: 'auto_proceed',
  uiMode: 'drawer',
  behavior: 'skipClick',
  autoProceedDelay: 25,
};

const silentConfig: NormalizedConfirmationConfig = {
  kind: 'silent',
  uiMode: 'none',
};

const invalidSilentBehavior = {
  kind: 'silent',
  uiMode: 'none',
  // @ts-expect-error Silent normalized config cannot carry visible UI behavior.
  behavior: 'requireClick',
} satisfies NormalizedConfirmationConfig;

const invalidSilentDelay = {
  kind: 'silent',
  uiMode: 'none',
  autoProceedDelay: 0,
  // @ts-expect-error Silent normalized config cannot carry visible UI timing.
} satisfies NormalizedConfirmationConfig;

const invalidRequireClickDelay = {
  kind: 'interactive',
  uiMode: 'modal',
  behavior: 'requireClick',
  autoProceedDelay: 10,
  // @ts-expect-error Require-click UI cannot carry auto-proceed timing.
} satisfies NormalizedConfirmationConfig;

const invalidAutoProceedMissingDelay = {
  kind: 'auto_proceed',
  uiMode: 'drawer',
  behavior: 'skipClick',
  // @ts-expect-error Auto-proceed UI must carry an explicit normalized delay.
} satisfies NormalizedConfirmationConfig;

// Raw boundary shapes may include behavior for uiMode none; normalization strips it.
normalizeConfirmationConfig({
  uiMode: 'none',
  behavior: 'requireClick',
  autoProceedDelay: 999,
});

void visibleRequireClick;
void visibleAutoProceed;
void silentConfig;
void invalidSilentBehavior;
void invalidSilentDelay;
void invalidRequireClickDelay;
void invalidAutoProceedMissingDelay;
