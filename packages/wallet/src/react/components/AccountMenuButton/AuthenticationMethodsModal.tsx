import React, { useEffect } from 'react';
import type {
  LinkedDeviceSummaryV1,
  LinkedOwnerCredentialMetadataV1,
  OwnerDeviceSummaryV1,
} from '@shared/device-linking';
import type { WalletAuthMethodBinding } from '@shared/utils/walletCapabilityBindings';
import { Theme, useTheme } from '../theme';
import { useSeams } from '../../context';
import { KeyIcon } from './icons/KeyIcon';
import { MailIcon } from './icons/MailIcon';
import './LinkedDevicesModal.css';

export interface AuthenticationMethodsModalProps {
  readonly walletId: string | null;
  readonly isOpen: boolean;
  readonly onClose: () => void;
}

type AuthenticationMethodView = {
  readonly kind: 'passkey' | 'email_otp';
  readonly walletAuthMethodId: string;
  readonly credential: LinkedOwnerCredentialMetadataV1;
};

type CurrentAuthorityInventory =
  | {
      readonly kind: 'owner_authority';
      readonly authorityId: string;
      readonly methods: readonly AuthenticationMethodView[];
    }
  | {
      readonly kind: 'linked_authority';
      readonly deviceId: string;
      readonly methods: readonly AuthenticationMethodView[];
    };

type LoadState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'loading' }
  | { readonly kind: 'loaded'; readonly inventory: CurrentAuthorityInventory }
  | { readonly kind: 'error'; readonly message: string };

type ActionState =
  | { readonly kind: 'idle' }
  | { readonly kind: 'adding'; readonly method: 'passkey' | 'email_otp' }
  | { readonly kind: 'confirming_revoke'; readonly method: AuthenticationMethodView }
  | { readonly kind: 'revoking'; readonly method: AuthenticationMethodView }
  | { readonly kind: 'error'; readonly message: string };

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  return 'Try again.';
}

function configuredWalletRpId(seams: ReturnType<typeof useSeams>['seams']): string {
  const configured = String(seams.configs.wallet.iframe?.rpIdOverride || '').trim();
  if (configured) return configured;
  if (typeof window !== 'undefined' && window.location.hostname) return window.location.hostname;
  throw new Error('Passkey addition requires a configured relying-party ID.');
}

function activeLinkedDevices(
  devices: readonly LinkedDeviceSummaryV1[],
): readonly LinkedDeviceSummaryV1[] {
  return devices.filter((device) => device.state === 'active');
}

function methodView(credential: LinkedOwnerCredentialMetadataV1): AuthenticationMethodView {
  return {
    kind: credential.kind,
    walletAuthMethodId: String(credential.walletAuthMethodId),
    credential,
  };
}

function requireValidMethodSet(
  credentials: readonly LinkedOwnerCredentialMetadataV1[],
): readonly AuthenticationMethodView[] {
  const methods = credentials.map(methodView);
  const passkeys = methods.filter((method) => method.kind === 'passkey');
  const emailMethods = methods.filter((method) => method.kind === 'email_otp');
  if (passkeys.length > 1 || emailMethods.length > 1) {
    throw new Error('This device authority has duplicate authentication methods.');
  }
  if (methods.length === 0) {
    throw new Error('The selected device authority has no active authentication method.');
  }
  return methods;
}

function currentAuthorityInventory(input: {
  readonly selectedBinding: WalletAuthMethodBinding;
  readonly ownerDevices: readonly OwnerDeviceSummaryV1[];
  readonly devices: readonly LinkedDeviceSummaryV1[];
}): CurrentAuthorityInventory {
  const selectedMethodId = String(input.selectedBinding.walletAuthMethodId);
  const ownerMatch = input.ownerDevices.find(
    (owner) => String(owner.credential.walletAuthMethodId) === selectedMethodId,
  );
  const linkedDevices = activeLinkedDevices(input.devices);
  const linkedMatch = linkedDevices.find(
    (device) => String(device.credential.walletAuthMethodId) === selectedMethodId,
  );
  if (ownerMatch && linkedMatch) {
    throw new Error('The selected authentication method maps to multiple device authorities.');
  }
  if (ownerMatch) {
    const authorityId = String(ownerMatch.walletAuthorityId);
    const credentials = input.ownerDevices
      .filter((owner) => String(owner.walletAuthorityId) === authorityId)
      .map((owner) => owner.credential);
    return {
      kind: 'owner_authority',
      authorityId,
      methods: requireValidMethodSet(credentials),
    };
  }
  if (linkedMatch) {
    const deviceId = String(linkedMatch.deviceId);
    const credentials = linkedDevices
      .filter((device) => String(device.deviceId) === deviceId)
      .map((device) => device.credential);
    return {
      kind: 'linked_authority',
      deviceId,
      methods: requireValidMethodSet(credentials),
    };
  }
  throw new Error('The selected authentication method is unavailable on this device authority.');
}

function focusableDialogElements(dialog: HTMLElement): HTMLElement[] {
  return Array.from(
    dialog.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
    ),
  );
}

function methodTitle(method: AuthenticationMethodView): string {
  return method.kind === 'passkey' ? 'Passkey' : 'Email OTP';
}

function methodDescription(method: AuthenticationMethodView): string {
  if (method.credential.kind === 'email_otp') return 'Email verification code';
  const provider = method.credential.device.providerLabel ?? method.credential.device.provider;
  return provider ? `${provider} passkey` : method.credential.device.label;
}

export const AuthenticationMethodsModal: React.FC<AuthenticationMethodsModalProps> = ({
  walletId,
  isOpen,
  onClose,
}) => {
  const { seams, loginState, refreshLoginState } = useSeams();
  const [loadState, setLoadState] = React.useState<LoadState>({ kind: 'idle' });
  const [initialContentReady, setInitialContentReady] = React.useState(false);
  const [actionState, setActionState] = React.useState<ActionState>({ kind: 'idle' });
  const [emailAddress, setEmailAddress] = React.useState('');
  const [announcement, setAnnouncement] = React.useState('');
  const loadSequence = React.useRef(0);
  const seamsRef = React.useRef(seams);
  const loginStateRef = React.useRef(loginState);
  const refreshLoginStateRef = React.useRef(refreshLoginState);
  const dialogRef = React.useRef<HTMLDivElement>(null);
  const previousFocusRef = React.useRef<HTMLElement | null>(null);
  const emailInputId = React.useId();
  const { theme, tokens } = useTheme();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );
  seamsRef.current = seams;
  loginStateRef.current = loginState;
  refreshLoginStateRef.current = refreshLoginState;

  const selectedWalletAuthMethodId =
    loginState.isLoggedIn && loginState.currentAuthMethod.kind === 'selected'
      ? String(loginState.currentAuthMethod.binding.walletAuthMethodId)
      : null;

  const loadInventory = React.useCallback(async () => {
    if (!walletId) {
      setLoadState({ kind: 'error', message: 'Wallet identity is unavailable. Try again.' });
      setInitialContentReady(true);
      return;
    }
    if (!selectedWalletAuthMethodId) {
      setLoadState({ kind: 'error', message: 'Unlock this wallet to manage authentication.' });
      setInitialContentReady(true);
      return;
    }
    const currentLoginState = loginStateRef.current;
    if (!currentLoginState.isLoggedIn || currentLoginState.currentAuthMethod.kind !== 'selected') {
      setLoadState({ kind: 'error', message: 'Unlock this wallet to manage authentication.' });
      setInitialContentReady(true);
      return;
    }
    const sequence = loadSequence.current + 1;
    loadSequence.current = sequence;
    setLoadState({ kind: 'loading' });
    try {
      const result = await seamsRef.current.devices.listLinkedDevices({
        walletId,
        limit: 50,
        cursor: null,
      });
      const inventory = currentAuthorityInventory({
        selectedBinding: currentLoginState.currentAuthMethod.binding,
        ownerDevices: result.ownerDevices,
        devices: result.devices,
      });
      if (loadSequence.current === sequence) {
        setLoadState({ kind: 'loaded', inventory });
        setInitialContentReady(true);
      }
    } catch (error: unknown) {
      if (loadSequence.current === sequence) {
        setLoadState({ kind: 'error', message: errorMessage(error) });
        setInitialContentReady(true);
      }
    }
  }, [selectedWalletAuthMethodId, walletId]);

  const handleDialogKeyDown = React.useCallback(
    (event: KeyboardEvent) => {
      if (event.key === 'Escape' || event.key === 'Esc') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !dialogRef.current) return;
      const focusable = focusableDialogElements(dialogRef.current);
      if (focusable.length === 0) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );

  useEffect(() => {
    if (!isOpen || !initialContentReady) return;
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialogRef.current?.focus({ preventScroll: true });
    window.addEventListener('keydown', handleDialogKeyDown);
    return () => {
      window.removeEventListener('keydown', handleDialogKeyDown);
      previousFocusRef.current?.focus();
      previousFocusRef.current = null;
    };
  }, [handleDialogKeyDown, initialContentReady, isOpen]);

  useEffect(() => {
    if (!isOpen) {
      loadSequence.current += 1;
      setLoadState({ kind: 'idle' });
      setInitialContentReady(false);
      setActionState({ kind: 'idle' });
      setEmailAddress('');
      setAnnouncement('');
      return;
    }
    void loadInventory();
  }, [isOpen, loadInventory]);

  const addMethod = React.useCallback(
    async (method: 'passkey' | 'email_otp') => {
      if (!walletId || actionState.kind === 'adding') return;
      const normalizedEmail = emailAddress.trim();
      if (method === 'email_otp' && !normalizedEmail) {
        setActionState({ kind: 'error', message: 'Enter the email address to verify.' });
        return;
      }
      setActionState({ kind: 'adding', method });
      setAnnouncement(method === 'passkey' ? 'Adding a passkey…' : 'Adding Email OTP…');
      try {
        if (method === 'passkey') {
          await seamsRef.current.registration.addPasskey({
            walletId,
            rpId: configuredWalletRpId(seamsRef.current),
          });
        } else {
          await seamsRef.current.registration.addEmailOtp({
            walletId,
            emailAddress: normalizedEmail,
          });
        }
        await refreshLoginStateRef.current(walletId);
        setEmailAddress('');
        setActionState({ kind: 'idle' });
        setAnnouncement(method === 'passkey' ? 'Passkey added.' : 'Email OTP added.');
        await loadInventory();
      } catch (error: unknown) {
        setActionState({ kind: 'error', message: errorMessage(error) });
      }
    },
    [actionState.kind, emailAddress, loadInventory, walletId],
  );

  const revokeMethod = React.useCallback(async () => {
    if (!walletId || actionState.kind !== 'confirming_revoke') return;
    const method = actionState.method;
    setActionState({ kind: 'revoking', method });
    setAnnouncement(`Removing ${methodTitle(method)}…`);
    try {
      await seamsRef.current.registration.revokeAuthMethod({
        walletId,
        walletAuthMethodId: method.walletAuthMethodId,
      });
      await refreshLoginStateRef.current(walletId);
      onClose();
    } catch (error: unknown) {
      setActionState({ kind: 'error', message: errorMessage(error) });
    }
  }, [actionState, onClose, walletId]);

  if (!isOpen) return null;

  const inventory = loadState.kind === 'loaded' ? loadState.inventory : null;
  const methods = inventory?.methods ?? [];
  const hasPasskey = methods.some((method) => method.kind === 'passkey');
  const hasEmailOtp = methods.some((method) => method.kind === 'email_otp');
  const actionInProgress = actionState.kind === 'adding' || actionState.kind === 'revoking';

  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <div
        className={`w3a-linked-devices-modal-backdrop theme-${theme}`}
        role="presentation"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) onClose();
        }}
      >
        {!initialContentReady ? (
          <div className="w3a-linked-devices-modal-live" role="status" aria-live="polite">
            Checking authentication methods…
          </div>
        ) : null}
        <div
          ref={dialogRef}
          className="w3a-linked-devices-modal-content w3a-auth-methods-modal-content"
          hidden={!initialContentReady}
          role="dialog"
          aria-modal="true"
          aria-labelledby="w3a-auth-methods-modal-title"
          tabIndex={-1}
        >
          <button
            type="button"
            className="w3a-linked-devices-modal-close"
            onClick={onClose}
            aria-label="Close authentication methods"
          >
            ✕
          </button>
          <h2 id="w3a-auth-methods-modal-title" className="w3a-linked-devices-modal-title">
            Authentication methods
          </h2>
          <p className="w3a-auth-methods-modal-intro">Manage how this device unlocks the wallet.</p>

          <div className="w3a-linked-devices-modal-body">
            {loadState.kind === 'loading' || loadState.kind === 'idle' ? (
              <div className="w3a-linked-devices-modal-placeholder" role="status">
                Checking authentication methods…
              </div>
            ) : null}

            {loadState.kind === 'error' ? (
              <div className="w3a-linked-devices-modal-placeholder" role="alert">
                <span>Unable to load authentication methods: {loadState.message}</span>
                <button
                  type="button"
                  className="w3a-linked-devices-modal-secondary"
                  onClick={() => void loadInventory()}
                >
                  Try again
                </button>
              </div>
            ) : null}

            {inventory ? (
              <ul className="w3a-linked-devices-modal-list w3a-linked-devices-modal-list--grouped">
                {methods.map((method) => {
                  const confirming =
                    actionState.kind === 'confirming_revoke' &&
                    actionState.method.walletAuthMethodId === method.walletAuthMethodId;
                  const revoking =
                    actionState.kind === 'revoking' &&
                    actionState.method.walletAuthMethodId === method.walletAuthMethodId;
                  return (
                    <li
                      key={method.walletAuthMethodId}
                      className="w3a-linked-devices-modal-item w3a-linked-devices-modal-item--row"
                    >
                      <span className="w3a-linked-devices-modal-item-icon" aria-hidden="true">
                        {method.kind === 'passkey' ? (
                          <KeyIcon size={20} strokeWidth={1.75} />
                        ) : (
                          <MailIcon size={20} strokeWidth={1.75} />
                        )}
                      </span>
                      <div className="w3a-linked-devices-modal-item-content">
                        <div className="w3a-linked-devices-modal-item-main">
                          <span className="w3a-linked-devices-modal-item-name">
                            {methodTitle(method)}
                          </span>
                          <span className="w3a-linked-devices-modal-standing tone-active">
                            Active
                          </span>
                        </div>
                        <div className="w3a-linked-devices-modal-item-detail">
                          {methodDescription(method)}
                        </div>
                        {confirming ? (
                          <div className="w3a-linked-devices-modal-confirm">
                            <span>
                              Remove {methodTitle(method)} from this device? You will need the other
                              active method to unlock it.
                            </span>
                            <div className="w3a-linked-devices-modal-confirm-actions">
                              <button
                                type="button"
                                className="w3a-linked-devices-modal-secondary"
                                onClick={() => setActionState({ kind: 'idle' })}
                              >
                                Keep it
                              </button>
                              <button
                                type="button"
                                className="w3a-linked-devices-modal-danger"
                                onClick={() => void revokeMethod()}
                              >
                                Remove method
                              </button>
                            </div>
                          </div>
                        ) : methods.length > 1 ? null : (
                          <span className="w3a-linked-devices-modal-item-detail">
                            Add another method before removing this one.
                          </span>
                        )}
                      </div>
                      {!confirming && methods.length > 1 ? (
                        <button
                          type="button"
                          className="w3a-linked-devices-modal-secondary w3a-linked-devices-modal-remove"
                          disabled={actionInProgress}
                          aria-label={`Remove ${methodTitle(method)}`}
                          onClick={() => setActionState({ kind: 'confirming_revoke', method })}
                        >
                          {revoking ? 'Removing…' : 'Remove'}
                        </button>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            ) : null}

            {inventory && !hasPasskey ? (
              <section className="w3a-linked-devices-modal-add-method">
                <h3>Add Passkey</h3>
                <p className="w3a-linked-devices-modal-security-note">
                  Use a passkey from this device to unlock the wallet.
                </p>
                <button
                  type="button"
                  className="w3a-linked-devices-modal-secondary"
                  disabled={actionInProgress}
                  onClick={() => void addMethod('passkey')}
                >
                  {actionState.kind === 'adding' && actionState.method === 'passkey'
                    ? 'Adding…'
                    : 'Add passkey'}
                </button>
              </section>
            ) : null}

            {inventory && !hasEmailOtp ? (
              <section className="w3a-linked-devices-modal-add-method">
                <h3>Add Email OTP</h3>
                <form
                  className="w3a-linked-devices-modal-otp-form"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void addMethod('email_otp');
                  }}
                >
                  <label htmlFor={emailInputId}>Email address</label>
                  <input
                    id={emailInputId}
                    className="w3a-linked-devices-modal-otp-input"
                    type="email"
                    autoComplete="email"
                    required
                    value={emailAddress}
                    disabled={actionInProgress}
                    onChange={(event) => {
                      setEmailAddress(event.currentTarget.value);
                      if (actionState.kind === 'error') setActionState({ kind: 'idle' });
                    }}
                  />
                  <button
                    type="submit"
                    className="w3a-linked-devices-modal-secondary"
                    disabled={actionInProgress}
                  >
                    {actionState.kind === 'adding' && actionState.method === 'email_otp'
                      ? 'Adding…'
                      : 'Add Email OTP'}
                  </button>
                </form>
              </section>
            ) : null}

            {actionState.kind === 'error' ? (
              <div className="w3a-linked-devices-modal-error" role="alert">
                {actionState.message}
              </div>
            ) : null}

            <div className="w3a-linked-devices-modal-live" role="status" aria-live="polite">
              {announcement}
            </div>
          </div>
        </div>
      </div>
    </Theme>
  );
};

export default AuthenticationMethodsModal;
