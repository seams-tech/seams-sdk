import React, { useEffect } from 'react';
import type {
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
  LinkedOwnerCredentialMetadataV1,
  OwnerDeviceSummaryV1,
} from '@shared/device-linking';
import {
  computeWalletAuthMethodRevokeOperationFingerprintV1,
  type WalletAuthMethodRevocationProof,
} from '@shared/utils/registrationIntent';
import { parseWalletAuthMethodId, parseWalletId } from '@shared/utils/domainIds';
import { base64UrlDecode } from '@shared/utils/encoders';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import type { WalletAuthMethodBinding } from '@shared/utils/walletCapabilityBindings';
import { serializeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { Theme, useTheme } from '../theme';
import { useSeams } from '../../context';
import './LinkedDevicesModal.css';

export interface LinkedDevicesModalProps {
  walletId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

type LinkedDevicesLoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'loaded'; devices: readonly NumberedWalletDevice[] }
  | { kind: 'error'; message: string };

/**
 * One card in the list: either a founding owner passkey (registered or
 * recovered directly, removable only through auth-method revocation) or a
 * linked-device enrollment (removable here).
 */
type WalletDeviceView =
  | { readonly kind: 'owner'; readonly owner: OwnerDeviceSummaryV1 }
  | { readonly kind: 'linked'; readonly device: LinkedDeviceSummaryV1 };

type NumberedWalletDevice = {
  readonly view: WalletDeviceView;
  readonly deviceNumber: number;
};

type RevokeState =
  | { kind: 'idle' }
  | { kind: 'confirming'; walletAuthMethodId: string }
  | { kind: 'working'; walletAuthMethodId: string }
  | {
      kind: 'email_otp';
      walletAuthMethodId: string;
      requestedAtMs: number;
      description: string;
      challengeId: string;
      ownerProofBindingDigest: string;
      emailHint: string | null;
      otpCode: string;
      submitting: boolean;
      error: string | null;
    }
  | { kind: 'error'; message: string };

type PasskeyWalletAuthMethodBinding = Extract<
  WalletAuthMethodBinding,
  { readonly kind: 'passkey' }
>;
type EmailOtpWalletAuthMethodBinding = Extract<
  WalletAuthMethodBinding,
  { readonly kind: 'email_otp' }
>;
type RevokeSourceMethod =
  | {
      readonly kind: 'passkey';
      readonly bindings: readonly [
        PasskeyWalletAuthMethodBinding,
        ...PasskeyWalletAuthMethodBinding[],
      ];
    }
  | { readonly kind: 'email_otp'; readonly binding: EmailOtpWalletAuthMethodBinding };

function requireWalletId(value: string) {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireWalletAuthMethodId(value: string) {
  const parsed = parseWalletAuthMethodId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function buildRevokeOperationFingerprint(input: {
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly requestedAtMs: number;
}) {
  return await computeWalletAuthMethodRevokeOperationFingerprintV1({
    walletId: requireWalletId(input.walletId),
    targetWalletAuthMethodId: requireWalletAuthMethodId(input.walletAuthMethodId),
    requestedAtMs: input.requestedAtMs,
  });
}

async function collectPasskeyRevokeProof(input: {
  readonly bindings: readonly [PasskeyWalletAuthMethodBinding, ...PasskeyWalletAuthMethodBinding[]];
  readonly operationFingerprintDigest: string;
}): Promise<WalletAuthMethodRevocationProof> {
  if (typeof navigator === 'undefined' || typeof navigator.credentials?.get !== 'function') {
    throw new Error('Passkey authorization is unavailable in this browser');
  }
  const [firstBinding, ...remainingBindings] = input.bindings;
  if (
    remainingBindings.some(
      (binding) => String(binding.scope.rpId) !== String(firstBinding.scope.rpId),
    )
  ) {
    throw new Error('Passkey authorization methods use different relying-party IDs');
  }
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: base64UrlDecode(input.operationFingerprintDigest),
      rpId: String(firstBinding.scope.rpId),
      allowCredentials: input.bindings.map((binding) => ({
        type: 'public-key',
        id: base64UrlDecode(binding.credentialIdB64u),
      })),
      userVerification: 'required',
      timeout: 60_000,
    },
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error('Passkey authorization did not return a credential');
  }
  return {
    kind: 'webauthn_assertion',
    rpId: firstBinding.scope.rpId,
    credential: serializeAuthenticationCredential(credential),
    expectedChallengeDigestB64u: input.operationFingerprintDigest,
  };
}

function revokeOutcomeAnnouncement(
  result: LinkedDeviceRevokeResultV1,
  description: string,
): string {
  switch (result.kind) {
    case 'revoked':
      return `${description} can no longer use this wallet.`;
    case 'not_found':
      return `${description} was already removed.`;
    case 'conflict':
      return 'The wallet changed before removal completed. The final wallet method cannot be removed.';
    case 'unauthorized':
      return 'Fresh authorization from another wallet method is required.';
  }
}

function resolveRevokeSourceMethod(
  binding: WalletAuthMethodBinding,
  walletId: string,
  targetWalletAuthMethodId: string,
): RevokeSourceMethod {
  const sourceWalletId =
    binding.kind === 'passkey' ? binding.scope.wallet.walletId : binding.wallet.walletId;
  if (String(sourceWalletId) !== walletId) {
    throw new Error('Unlock this wallet with a sibling authentication method first.');
  }
  if (String(binding.walletAuthMethodId) === targetWalletAuthMethodId) {
    throw new Error('Unlock with the sibling authentication method before removing this one.');
  }
  return binding.kind === 'passkey'
    ? { kind: 'passkey', bindings: [binding] }
    : { kind: 'email_otp', binding };
}

function viewCreatedAtMs(view: WalletDeviceView): number {
  return view.kind === 'owner' ? view.owner.createdAtMs : view.device.createdAtMs;
}

function viewLastActivityAtMs(view: WalletDeviceView): number {
  return view.kind === 'owner' ? view.owner.lastActivityAtMs : view.device.lastActivityAtMs;
}

function viewCredential(view: WalletDeviceView): LinkedOwnerCredentialMetadataV1 {
  return view.kind === 'owner' ? view.owner.credential : view.device.credential;
}

/**
 * The card's stable identity for expand/remove state. Linked devices carry a
 * LinkedDeviceId; founding owners have only their credential.
 */
function viewId(view: WalletDeviceView): string {
  return view.kind === 'owner'
    ? String(view.owner.credential.walletAuthMethodId)
    : String(view.device.deviceId);
}

/** The identifier a person can match against their other device. */
function viewDisplayId(view: WalletDeviceView): string {
  return view.kind === 'owner'
    ? String(view.owner.credential.credentialIdB64u ?? view.owner.credential.walletAuthMethodId)
    : String(view.device.deviceId);
}

/**
 * Founding owners and linked enrollments in one numbered list, oldest first.
 * Revoked devices are historical records, not devices the owner can manage.
 */
function visibleWalletDevices(
  ownerDevices: readonly OwnerDeviceSummaryV1[],
  devices: readonly LinkedDeviceSummaryV1[],
): readonly NumberedWalletDevice[] {
  const views: WalletDeviceView[] = [
    ...ownerDevices.map((owner): WalletDeviceView => ({ kind: 'owner', owner })),
    ...devices.map((device): WalletDeviceView => ({ kind: 'linked', device })),
  ];
  return views
    .sort(
      (left, right) =>
        viewCreatedAtMs(left) - viewCreatedAtMs(right) || viewId(left).localeCompare(viewId(right)),
    )
    .map((view, index) => ({ view, deviceNumber: index + 1 }))
    .filter(({ view }) => view.kind === 'owner' || view.device.state !== 'revoked');
}

function isActiveWalletMethod(view: WalletDeviceView): boolean {
  return view.kind === 'owner' || view.device.state === 'active';
}

function canRemoveWalletMethod(
  target: WalletDeviceView,
  devices: readonly NumberedWalletDevice[],
): boolean {
  const activeMethodCount = devices.filter(({ view }) => isActiveWalletMethod(view)).length;
  return isActiveWalletMethod(target) ? activeMethodCount > 1 : activeMethodCount > 0;
}

/**
 * Plain-language state for one device. The wire model carries five states and a
 * revocation epoch; a person only needs to know whether the device can still
 * reach the wallet right now. Founding owners in the list are active by
 * construction — the projection only serves active owner credentials.
 */
function deviceStanding(view: WalletDeviceView): {
  readonly label: string;
  readonly tone: 'active' | 'pending' | 'off';
} {
  if (view.kind === 'owner') return { label: 'Original device', tone: 'active' };
  switch (view.device.state) {
    case 'active':
      return { label: 'Can use this wallet', tone: 'active' };
    case 'provisioning':
      return { label: 'Finishing setup', tone: 'pending' };
    case 'suspended':
      return { label: 'Paused', tone: 'off' };
    case 'expired':
      return { label: 'Expired', tone: 'off' };
    case 'revoked':
      return { label: 'Removed', tone: 'off' };
  }
}

/** "today" / "yesterday" / a plain date — never a timestamp with seconds. */
function friendlyDay(value: number, now: number): string {
  const then = new Date(value);
  const startOfToday = new Date(now);
  startOfToday.setHours(0, 0, 0, 0);
  const dayMs = 24 * 60 * 60 * 1000;
  const daysAgo = Math.floor((startOfToday.getTime() - then.setHours(0, 0, 0, 0)) / dayMs);
  if (daysAgo <= 0) return 'today';
  if (daysAgo === 1) return 'yesterday';
  if (daysAgo < 7) return `${daysAgo} days ago`;
  return new Date(value).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function shortDisplayId(value: string): string {
  return value.length <= 12 ? value : `…${value.slice(-8)}`;
}

/**
 * The one description the card heading, the removal confirmation, and every
 * live announcement share. Credential labels repeat across cards — two platform
 * passkeys are both "Platform passkey" — so the stable ID suffix is what makes
 * a sentence name a single card rather than a category of them.
 */
function credentialDescription(credential: LinkedOwnerCredentialMetadataV1): string {
  switch (credential.kind) {
    case 'passkey':
      return credential.device.label;
    case 'email_otp':
      return 'Email OTP';
  }
}

function credentialSecondaryDescription(
  credential: LinkedOwnerCredentialMetadataV1,
): string | null {
  switch (credential.kind) {
    case 'email_otp':
      return null;
    case 'passkey': {
      const metadata = credential.device;
      const provider = metadata.providerLabel ?? metadata.provider;
      const sync = metadata.synced ? 'Synced passkey' : 'Passkey';
      return provider ? `${provider} · ${sync}` : sync;
    }
  }
}

function deviceDescription(view: WalletDeviceView, deviceNumber: number): string {
  return `Device ${deviceNumber}, ${credentialDescription(viewCredential(view))} (ID ${shortDisplayId(viewDisplayId(view))})`;
}

function linkedDevicesLoadErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  return 'Try again.';
}

const LINKED_DEVICES_LOAD_TIMEOUT_MS = 20_000;

function withLinkedDevicesLoadTimeout<T>(promise: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      reject(new Error('Loading your devices timed out. Try again.'));
    }, LINKED_DEVICES_LOAD_TIMEOUT_MS);
    promise.then(
      (value) => {
        clearTimeout(timeoutId);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timeoutId);
        reject(error);
      },
    );
  });
}

function focusableDialogElements(dialog: HTMLElement): HTMLElement[] {
  return Array.from(
    dialog.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  );
}

export const LinkedDevicesModal: React.FC<LinkedDevicesModalProps> = ({
  walletId,
  isOpen,
  onClose,
}) => {
  const { seams, loginState } = useSeams();
  const [loadState, setLoadState] = React.useState<LinkedDevicesLoadState>({ kind: 'idle' });
  const [initialContentReady, setInitialContentReady] = React.useState(false);
  const [revokeState, setRevokeState] = React.useState<RevokeState>({ kind: 'idle' });
  const [announcement, setAnnouncement] = React.useState('');
  /** Device IDs are identifiers, not secrets, but printing one in full by
   * default buries the rest of the card. One card at a time may expand. */
  const [expandedDeviceId, setExpandedDeviceId] = React.useState<string | null>(null);
  const loadSeq = React.useRef(0);
  const seamsRef = React.useRef(seams);
  const dialogRef = React.useRef<HTMLDivElement>(null);
  const closeButtonRef = React.useRef<HTMLButtonElement>(null);
  const otpInputRef = React.useRef<HTMLInputElement>(null);
  const otpInputId = React.useId();
  const previousFocusRef = React.useRef<HTMLElement | null>(null);
  const { theme, tokens } = useTheme();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );
  seamsRef.current = seams;

  const loadDevices = React.useCallback(async () => {
    const seq = loadSeq.current + 1;
    loadSeq.current = seq;
    if (!walletId) {
      setLoadState({ kind: 'error', message: 'Wallet identity is unavailable. Try again.' });
      setInitialContentReady(true);
      return;
    }
    setLoadState({ kind: 'loading' });
    try {
      const result = await withLinkedDevicesLoadTimeout(
        seamsRef.current.devices.listLinkedDevices({ walletId, limit: 50, cursor: null }),
      );
      if (loadSeq.current === seq) {
        setLoadState({
          kind: 'loaded',
          devices: visibleWalletDevices(result.ownerDevices, result.devices),
        });
        setInitialContentReady(true);
      }
    } catch (error: unknown) {
      if (loadSeq.current === seq) {
        setLoadState({ kind: 'error', message: linkedDevicesLoadErrorMessage(error) });
        setInitialContentReady(true);
      }
    }
  }, [walletId]);

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
    closeButtonRef.current?.focus();
    window.addEventListener('keydown', handleDialogKeyDown);
    return () => {
      window.removeEventListener('keydown', handleDialogKeyDown);
      previousFocusRef.current?.focus();
      previousFocusRef.current = null;
    };
  }, [handleDialogKeyDown, initialContentReady, isOpen]);

  useEffect(() => {
    if (!isOpen) {
      loadSeq.current += 1;
      setLoadState({ kind: 'idle' });
      setInitialContentReady(false);
      setRevokeState({ kind: 'idle' });
      setAnnouncement('');
      setExpandedDeviceId(null);
      return;
    }
    void loadDevices();
  }, [isOpen, loadDevices]);

  useEffect(() => {
    if (revokeState.kind === 'email_otp') otpInputRef.current?.focus();
  }, [revokeState.kind]);

  const finishRevocation = React.useCallback(
    async (result: LinkedDeviceRevokeResultV1, description: string) => {
      const message = revokeOutcomeAnnouncement(result, description);
      setAnnouncement(message);
      switch (result.kind) {
        case 'revoked':
        case 'not_found':
          setRevokeState({ kind: 'idle' });
          await loadDevices();
          return;
        case 'conflict':
        case 'unauthorized':
          setRevokeState({ kind: 'error', message });
          return;
      }
    },
    [loadDevices],
  );

  const revokeMethod = React.useCallback(
    async (view: WalletDeviceView, deviceNumber: number) => {
      if (!walletId) return;
      const walletAuthMethodId = String(viewCredential(view).walletAuthMethodId);
      const description = deviceDescription(view, deviceNumber);
      try {
        if (!loginState.isLoggedIn || loginState.currentAuthMethod.kind !== 'selected') {
          throw new Error('Unlock this wallet with a sibling authentication method first.');
        }
        const sourceMethod = resolveRevokeSourceMethod(
          loginState.currentAuthMethod.binding,
          walletId,
          walletAuthMethodId,
        );
        const requestedAtMs = Date.now();
        const operationFingerprintDigest = await buildRevokeOperationFingerprint({
          walletId,
          walletAuthMethodId,
          requestedAtMs,
        });
        if (sourceMethod.kind === 'email_otp') {
          /* No method id here: both wallet methods can share this email, so a
             factor-derived id cannot name the session's method. The wallet host
             binds the challenge to its exact selected active method. */
          const challenge = await seams.auth.requestEmailOtpChallenge({
            walletId,
            operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
            operationFingerprintDigest,
          });
          setRevokeState({
            kind: 'email_otp',
            walletAuthMethodId,
            requestedAtMs,
            description,
            challengeId: challenge.challengeId,
            ownerProofBindingDigest: challenge.ownerProofBindingDigest,
            emailHint: challenge.emailHint ?? null,
            otpCode: '',
            submitting: false,
            error: null,
          });
          setAnnouncement(`A verification code was sent for removing ${description}.`);
          return;
        }
        setRevokeState({ kind: 'working', walletAuthMethodId });
        setAnnouncement(`Removing ${description}…`);
        const sourceProof = await collectPasskeyRevokeProof({
          bindings: sourceMethod.bindings,
          operationFingerprintDigest,
        });
        const result = await seams.devices.revokeLinkedDevice({
          walletId,
          walletAuthMethodId,
          requestedAtMs,
          sourceProof,
        });
        await finishRevocation(result, description);
      } catch (error: unknown) {
        setRevokeState({ kind: 'error', message: linkedDevicesLoadErrorMessage(error) });
      }
    },
    [finishRevocation, loginState, seams, walletId],
  );

  const submitEmailOtpRevocation = React.useCallback(async () => {
    if (!walletId || revokeState.kind !== 'email_otp' || revokeState.submitting) return;
    const pending = revokeState;
    if (!pending.otpCode.trim()) {
      setRevokeState({ ...pending, error: 'Enter the verification code.' });
      return;
    }
    setRevokeState({ ...pending, submitting: true, error: null });
    setAnnouncement(`Removing ${pending.description}…`);
    try {
      const result = await seams.devices.revokeLinkedDevice({
        walletId,
        walletAuthMethodId: pending.walletAuthMethodId,
        requestedAtMs: pending.requestedAtMs,
        sourceProof: {
          kind: 'email_otp',
          challengeId: pending.challengeId,
          otpCode: pending.otpCode.trim(),
          ownerProofBindingDigest: pending.ownerProofBindingDigest,
        },
      });
      await finishRevocation(result, pending.description);
    } catch (error: unknown) {
      setRevokeState({
        ...pending,
        submitting: false,
        error: linkedDevicesLoadErrorMessage(error),
      });
    }
  }, [finishRevocation, revokeState, seams, walletId]);

  if (!isOpen) return null;

  const devices = loadState.kind === 'loaded' ? loadState.devices : [];
  const showEmpty = loadState.kind === 'loaded' && devices.length === 0;
  const selectedWalletAuthMethodId =
    loginState.isLoggedIn && loginState.currentAuthMethod.kind === 'selected'
      ? String(loginState.currentAuthMethod.binding.walletAuthMethodId)
      : null;

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
            Checking your devices…
          </div>
        ) : null}
        <div
          ref={dialogRef}
          className="w3a-linked-devices-modal-content"
          hidden={!initialContentReady}
          role="dialog"
          aria-modal="true"
          aria-labelledby="w3a-linked-devices-modal-title"
          tabIndex={-1}
        >
          <button
            ref={closeButtonRef}
            type="button"
            className="w3a-linked-devices-modal-close"
            onClick={onClose}
            aria-label="Close linked devices"
          >
            ✕
          </button>
          <h2 id="w3a-linked-devices-modal-title" className="w3a-linked-devices-modal-title">
            Your devices
          </h2>

          <div className="w3a-linked-devices-modal-body">
            {loadState.kind === 'loading' || loadState.kind === 'idle' ? (
              <div className="w3a-linked-devices-modal-placeholder">Checking your devices…</div>
            ) : null}

            {loadState.kind === 'error' ? (
              <div className="w3a-linked-devices-modal-placeholder" role="alert">
                <span>Unable to load your devices: {loadState.message}</span>
                <button
                  type="button"
                  className="w3a-linked-devices-modal-secondary"
                  onClick={() => void loadDevices()}
                >
                  Try again
                </button>
              </div>
            ) : null}

            {showEmpty ? (
              <div className="w3a-linked-devices-modal-placeholder">
                No other devices are using this wallet.
              </div>
            ) : null}

            {devices.length > 0 ? (
              <ul className="w3a-linked-devices-modal-list">
                {devices.map(({ view, deviceNumber }) => {
                  const cardId = viewId(view);
                  const displayId = viewDisplayId(view);
                  const secondaryDescription = credentialSecondaryDescription(viewCredential(view));
                  const standing = deviceStanding(view);
                  const walletAuthMethodId = String(viewCredential(view).walletAuthMethodId);
                  const isSelectedMethod = walletAuthMethodId === selectedWalletAuthMethodId;
                  const hasRemovableSibling = canRemoveWalletMethod(view, devices);
                  const confirming =
                    revokeState.kind === 'confirming' &&
                    revokeState.walletAuthMethodId === walletAuthMethodId;
                  const working =
                    revokeState.kind === 'working' &&
                    revokeState.walletAuthMethodId === walletAuthMethodId;
                  const awaitingEmailOtp =
                    revokeState.kind === 'email_otp' &&
                    revokeState.walletAuthMethodId === walletAuthMethodId;
                  const revocationInProgress =
                    revokeState.kind === 'working' || revokeState.kind === 'email_otp';
                  const fullIdShown = expandedDeviceId === cardId;
                  return (
                    <li key={cardId} className="w3a-linked-devices-modal-item">
                      <div className="w3a-linked-devices-modal-item-main">
                        <span className="w3a-linked-devices-modal-item-name">
                          Device {deviceNumber} &middot;{' '}
                          {credentialDescription(viewCredential(view))}
                        </span>
                        <span className={`w3a-linked-devices-modal-standing tone-${standing.tone}`}>
                          {standing.label}
                        </span>
                      </div>
                      <div className="w3a-linked-devices-modal-item-identity">
                        {secondaryDescription ? <span>{secondaryDescription}</span> : null}
                        {secondaryDescription ? <span aria-hidden="true">&middot;</span> : null}
                        {isSelectedMethod ? <span>Current unlock method</span> : null}
                        {isSelectedMethod ? <span aria-hidden="true">&middot;</span> : null}
                        <span className="w3a-linked-devices-modal-device-id">
                          ID {fullIdShown ? displayId : shortDisplayId(displayId)}
                        </span>
                        <button
                          type="button"
                          className="w3a-linked-devices-modal-disclosure"
                          aria-expanded={fullIdShown}
                          onClick={() => setExpandedDeviceId(fullIdShown ? null : cardId)}
                        >
                          {fullIdShown ? 'Hide full ID' : 'Show full ID'}
                        </button>
                      </div>
                      <div className="w3a-linked-devices-modal-item-detail">
                        Last used {friendlyDay(viewLastActivityAtMs(view), Date.now())}
                      </div>
                      {awaitingEmailOtp && revokeState.kind === 'email_otp' ? (
                        <form
                          className="w3a-linked-devices-modal-otp-form"
                          onSubmit={(event) => {
                            event.preventDefault();
                            void submitEmailOtpRevocation();
                          }}
                        >
                          <label htmlFor={otpInputId}>Verification code</label>
                          {revokeState.emailHint ? (
                            <span className="w3a-linked-devices-modal-item-detail">
                              Sent to {revokeState.emailHint}
                            </span>
                          ) : null}
                          <input
                            ref={otpInputRef}
                            id={otpInputId}
                            className="w3a-linked-devices-modal-otp-input"
                            type="text"
                            inputMode="numeric"
                            autoComplete="one-time-code"
                            pattern="[0-9]*"
                            maxLength={10}
                            value={revokeState.otpCode}
                            disabled={revokeState.submitting}
                            aria-invalid={revokeState.error ? 'true' : undefined}
                            aria-describedby={revokeState.error ? `${otpInputId}-error` : undefined}
                            onChange={(event) =>
                              setRevokeState({
                                ...revokeState,
                                otpCode: event.currentTarget.value,
                                error: null,
                              })
                            }
                          />
                          {revokeState.error ? (
                            <span
                              id={`${otpInputId}-error`}
                              className="w3a-linked-devices-modal-error"
                              role="alert"
                            >
                              {revokeState.error}
                            </span>
                          ) : null}
                          <div className="w3a-linked-devices-modal-confirm-actions">
                            <button
                              type="button"
                              className="w3a-linked-devices-modal-secondary"
                              disabled={revokeState.submitting}
                              onClick={() => setRevokeState({ kind: 'idle' })}
                            >
                              Keep it
                            </button>
                            <button
                              type="submit"
                              className="w3a-linked-devices-modal-danger"
                              disabled={revokeState.submitting}
                            >
                              {revokeState.submitting ? 'Removing…' : 'Verify and remove'}
                            </button>
                          </div>
                        </form>
                      ) : confirming ? (
                        <div className="w3a-linked-devices-modal-confirm">
                          <span>
                            Remove {deviceDescription(view, deviceNumber)}? It will lose access
                            right away.
                          </span>
                          <div className="w3a-linked-devices-modal-confirm-actions">
                            <button
                              type="button"
                              className="w3a-linked-devices-modal-secondary"
                              onClick={() => setRevokeState({ kind: 'idle' })}
                            >
                              Keep it
                            </button>
                            <button
                              type="button"
                              className="w3a-linked-devices-modal-danger"
                              onClick={() => void revokeMethod(view, deviceNumber)}
                            >
                              Yes, remove
                            </button>
                          </div>
                        </div>
                      ) : hasRemovableSibling && !isSelectedMethod ? (
                        <button
                          type="button"
                          className="w3a-linked-devices-modal-secondary"
                          disabled={revocationInProgress}
                          aria-label={`Remove ${deviceDescription(view, deviceNumber)}`}
                          onClick={() => setRevokeState({ kind: 'confirming', walletAuthMethodId })}
                        >
                          {working ? 'Removing…' : 'Remove'}
                        </button>
                      ) : hasRemovableSibling ? (
                        <span className="w3a-linked-devices-modal-item-detail">
                          Unlock with the sibling method to remove this one.
                        </span>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            ) : null}

            {revokeState.kind === 'error' ? (
              <div className="w3a-linked-devices-modal-error" role="alert">
                {revokeState.message}
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

export default LinkedDevicesModal;
