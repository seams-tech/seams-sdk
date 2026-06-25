import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { NormalizedConfirmationConfig } from '@/core/types/confirmationConfig';
import { normalizeConfirmationConfig } from '@/core/types/confirmationConfig';
import type { UiConfirmContext } from '../uiConfirm.types';
import type { UserConfirmRequest } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { UserConfirmationType } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import { needsExplicitActivation } from '@/react/deviceDetection';
import { isObject, isString } from '@shared/utils/validation';

/**
 * determineConfirmationConfig
 *
 * Computes the effective confirmation UI behavior used by the secure‑confirmation
 * flow by merging inputs and applying safe runtime rules.
 *
 * Order of precedence (highest → lowest):
 * 1) Request‑level override (request.confirmationConfig), when explicitly set.
 * 2) User preferences stored in the wallet host (from IndexedDB via ctx.userPreferencesManager).
 * 3) Runtime safety rules (wallet‑iframe registration/link flows) that may clamp behavior.
 *
 * Wallet‑iframe registration/link safety rule:
 * - When running inside the wallet-iframe host context, always clamp registration/link flows to
 *   `{ uiMode: 'modal', behavior: 'requireClick' }` so the user activation happens inside the iframe.
 *   This intentionally overrides both user preferences and request-level overrides.
 * - A wallet-iframe registration activation proof is the narrow exception for registration: the
 *   iframe-owned activation button already supplied the wallet-origin click.
 *
 * Notes
 * - The function is pure (does not mutate the input object) and safe to call multiple times.
 * - Unrelated options are preserved in all cases.
 */
export function determineConfirmationConfig(
  ctx: UiConfirmContext,
  request: UserConfirmRequest | undefined,
): NormalizedConfirmationConfig {
  // Merge request‑level override over user preferences
  // Important: drop undefined/null fields from the override so they don't clobber
  // persisted preferences (e.g., behavior) with an undefined value.
  const configBase = ctx.userPreferencesManager.getConfirmationConfig();
  const rawOverride = (request?.confirmationConfig || {}) as Partial<ConfirmationConfig>;
  const cleanedOverride = Object.fromEntries(
    Object.entries(rawOverride).filter(([, v]) => v !== undefined && v !== null),
  ) as Partial<ConfirmationConfig>;
  let cfg: ConfirmationConfig = { ...configBase, ...cleanedOverride } as ConfirmationConfig;

  // Default decrypt-private-key confirmations to 'none' UI. The flow collects
  // WebAuthn credentials silently and the worker may follow up with a
  // SHOW_SECURE_PRIVATE_KEY_UI request to display the key.
  if (request?.type === UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF) {
    return normalizeConfirmationConfig({
      uiMode: 'none',
      behavior: cfg.behavior,
      autoProceedDelay: cfg.autoProceedDelay,
    });
  }

  // Detect if running inside an iframe (wallet host context)
  const inIframe = window.self !== window.top;

  // On Safari/iOS or mobile devices without a fresh user activation,
  // clamp to a clickable UI to reliably satisfy WebAuthn requirements.
  // - If caller/user set uiMode: 'none', promote to 'modal' + requireClick
  // - If behavior is 'skipClick', upgrade to 'requireClick'
  // Use shared heuristic to decide if explicit activation is necessary
  if (needsExplicitActivation()) {
    const newUiMode: ConfirmationConfig['uiMode'] = cfg.uiMode === 'none' ? 'drawer' : cfg.uiMode;
    cfg = {
      ...cfg,
      uiMode: newUiMode,
      behavior: 'requireClick',
    } as ConfirmationConfig;
  }

  // In wallet-iframe host context, registration/link flows require an explicit
  // wallet-origin click. This keeps WebAuthn activation inside the iframe.
  if (
    inIframe &&
    request?.type &&
    (request.type === UserConfirmationType.REGISTER_ACCOUNT ||
      request.type === UserConfirmationType.LINK_DEVICE)
  ) {
    if (
      request.type === UserConfirmationType.REGISTER_ACCOUNT &&
      hasWalletIframeRegistrationActivation(request.payload)
    ) {
      return normalizeConfirmationConfig({
        uiMode: 'none',
        behavior: 'skipClick',
        autoProceedDelay: 0,
      });
    }
    return normalizeConfirmationConfig({
      uiMode: 'modal',
      behavior: 'requireClick',
      autoProceedDelay: cfg.autoProceedDelay,
    });
  }

  // Otherwise honor caller/user configuration
  return normalizeConfirmationConfig(cfg);
}

function hasWalletIframeRegistrationActivation(payload: unknown): boolean {
  if (!isObject(payload)) return false;
  const activation = (payload as { walletIframeActivation?: unknown }).walletIframeActivation;
  if (!isObject(activation)) return false;
  const proof = activation as { kind?: unknown; activationId?: unknown; activatedAtMs?: unknown };
  return (
    proof.kind === 'wallet_iframe_registration_activation_v1' &&
    isString(proof.activationId) &&
    proof.activationId.trim().length > 0 &&
    typeof proof.activatedAtMs === 'number' &&
    Number.isFinite(proof.activatedAtMs)
  );
}
