import React from 'react';
import type { StoredAccountOption } from '@/react/types';
import { WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import { AuthMenuMode } from '../authMenuTypes';
import { AccountExistsBadge } from './AccountExistsBadge';
import { usePostfixPosition } from './usePostfixPosition';

export interface PasskeyInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  postfixText?: string;
  isUsingExistingAccount?: boolean;
  targetExists?: boolean;
  accountOptions?: StoredAccountOption[];
  onProceed: () => void;
  /** Current signup mode for status badge */
  mode?: AuthMenuMode;
  /** Whether the current context is secure (HTTPS) */
  secure?: boolean;
  /** Whether the parent flow is waiting on passkey resolution */
  waiting?: boolean;
  readOnly?: boolean;
  onRerollValue?: () => void;
  rerollValueLabel?: string;
  rerollValueDisabled?: boolean;
}

type AccountOptionGroup = {
  label: 'Passkey' | 'Email OTP';
  accounts: StoredAccountOption[];
};

const AccountDropdownArrow: React.FC = () => (
  <svg
    className="w3a-account-dropdown-arrow"
    viewBox="0 0 24 24"
    aria-hidden="true"
    focusable="false"
  >
    <path d="M9.75 3h4.5v10.28l4.3-4.3 3.18 3.18L12 21.9l-9.73-9.74 3.18-3.18 4.3 4.3V3Z" />
  </svg>
);

const RerollValueIcon: React.FC = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    className="w3a-input-action-icon lucide lucide-refresh-cw-icon lucide-refresh-cw"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={2}
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
    focusable="false"
  >
    <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
    <path d="M21 3v5h-5" />
    <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
    <path d="M8 16H3v5" />
  </svg>
);

function groupAccountOptions(accountOptions?: StoredAccountOption[]): AccountOptionGroup[] {
  const uniqueAccounts = new Map<string, StoredAccountOption>();
  for (const option of accountOptions ?? []) {
    const walletId = String(option.walletId || '').trim();
    if (!walletId) continue;
    const displayName = String(option.displayName || walletId).trim() || walletId;
    uniqueAccounts.set(`${walletId}:${option.authMethod}:${displayName}`, {
      walletId,
      displayName,
      authMethod: option.authMethod,
      ...(typeof option.signerSlot === 'number' ? { signerSlot: option.signerSlot } : {}),
    });
  }

  const sortedAccounts = [...uniqueAccounts.values()].sort((a, b) =>
    a.displayName.localeCompare(b.displayName),
  );
  const passkeyAccounts = sortedAccounts.filter(
    (option) => option.authMethod === WALLET_AUTH_METHODS.passkey,
  );
  const emailOtpAccounts = sortedAccounts.filter(
    (option) => option.authMethod === WALLET_AUTH_METHODS.emailOtp,
  );
  const groups: AccountOptionGroup[] = [
    { label: 'Passkey', accounts: passkeyAccounts },
    { label: 'Email OTP', accounts: emailOtpAccounts },
  ];
  return groups.filter((group) => group.accounts.length > 0);
}

function findSelectedAccountOption(input: {
  value: string;
  accountOptions?: StoredAccountOption[];
}): StoredAccountOption | null {
  const value = String(input.value || '')
    .trim()
    .toLowerCase();
  if (!value) return null;
  for (const option of input.accountOptions ?? []) {
    const candidates = [option.walletId, option.displayName];
    for (const candidate of candidates) {
      if (
        String(candidate || '')
          .trim()
          .toLowerCase() === value
      )
        return option;
    }
  }
  return null;
}

function accountOptionSelected(account: StoredAccountOption, value: string): boolean {
  const normalizedValue = String(value || '')
    .trim()
    .toLowerCase();
  if (!normalizedValue) return false;
  const candidates = [account.walletId, account.displayName];
  for (const candidate of candidates) {
    if (
      String(candidate || '')
        .trim()
        .toLowerCase() === normalizedValue
    )
      return true;
  }
  return false;
}

function accountOptionTitle(account: StoredAccountOption): string {
  if (!shouldShowAccountWalletId(account)) return account.displayName;
  return `${account.displayName} ${account.walletId}`;
}

function shouldShowAccountWalletId(account: StoredAccountOption): boolean {
  return (
    account.authMethod === WALLET_AUTH_METHODS.emailOtp && account.walletId !== account.displayName
  );
}

function isEmailAddressLike(value: string): boolean {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(String(value || '').trim());
}

export const PasskeyInput: React.FC<PasskeyInputProps> = ({
  value,
  onChange,
  placeholder,
  postfixText,
  isUsingExistingAccount,
  targetExists,
  accountOptions,
  onProceed,
  mode,
  secure,
  waiting = false,
  readOnly = false,
  onRerollValue,
  rerollValueLabel = 'Generate another name',
  rerollValueDisabled = false,
}: PasskeyInputProps) => {
  const statusId = React.useId();
  const inputId = React.useId();
  const menuId = React.useId();
  const showAccountOptions = mode === AuthMenuMode.Login && !!accountOptions?.length;
  const accountGroups = React.useMemo(() => groupAccountOptions(accountOptions), [accountOptions]);
  const selectedAccount = React.useMemo(
    () => findSelectedAccountOption({ value, accountOptions }),
    [value, accountOptions],
  );
  const renderedValue =
    mode === AuthMenuMode.Login && selectedAccount ? selectedAccount.displayName : value;
  const suppressMissingLoginBadge =
    mode === AuthMenuMode.Login && isEmailAddressLike(renderedValue);
  const { bindInput, bindPostfix } = usePostfixPosition({ inputValue: renderedValue, gap: 1 });
  const [accountMenuOpen, setAccountMenuOpen] = React.useState(false);

  // Keep a stable ref to the input so we can manage focus across transitions
  const inputRef = React.useRef<HTMLInputElement | null>(null);
  const accountMenuRef = React.useRef<HTMLDivElement | null>(null);
  const prevWaitingRef = React.useRef<boolean>(waiting);

  const attachInputRef = React.useCallback(
    (el: HTMLInputElement | null) => {
      bindInput(el);
      inputRef.current = el;
    },
    [bindInput],
  );

  // Autofocus on initial mount when the input appears
  React.useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    try {
      el.focus();
      const len = el.value?.length ?? 0;
      if (len >= 0 && typeof el.setSelectionRange === 'function') {
        el.setSelectionRange(len, len);
      }
    } catch {
      // best-effort focus; ignore failures
    }
  }, []);

  // When returning from a waiting state (e.g., login/register attempt cancelled),
  // re-focus the input so users can keep typing without an extra click.
  React.useEffect(() => {
    const prev = prevWaitingRef.current;
    if (prev && !waiting && inputRef.current) {
      try {
        inputRef.current.focus();
        const len = inputRef.current.value?.length ?? 0;
        if (len >= 0 && typeof inputRef.current.setSelectionRange === 'function') {
          inputRef.current.setSelectionRange(len, len);
        }
      } catch {
        // ignore focus errors
      }
    }
    prevWaitingRef.current = waiting;
  }, [waiting]);

  React.useEffect(() => {
    if (!accountMenuOpen) return;
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (accountMenuRef.current?.contains(target)) return;
      setAccountMenuOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setAccountMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [accountMenuOpen]);

  React.useEffect(() => {
    if (!showAccountOptions || waiting) setAccountMenuOpen(false);
  }, [showAccountOptions, waiting]);

  const onEnter = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') onProceed();
  };

  return (
    <div className="w3a-passkey-row">
      <div className="w3a-input-pill">
        <div className="w3a-input-wrap">
          <input
            ref={attachInputRef}
            type="text"
            id={inputId}
            name="passkey"
            value={renderedValue}
            onChange={(e) => {
              if (readOnly) return;
              onChange(e.target.value);
            }}
            onKeyDown={onEnter}
            placeholder={placeholder}
            className="w3a-input"
            aria-describedby={statusId}
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            inputMode="text"
            readOnly={readOnly}
          />
          {postfixText && renderedValue.length > 0 && (
            <span
              title={isUsingExistingAccount ? 'Using saved account domain' : 'New account domain'}
              className={`w3a-postfix${isUsingExistingAccount ? ' is-existing' : ''}`}
              ref={bindPostfix}
            >
              {postfixText}
            </span>
          )}
          <AccountExistsBadge
            id={statusId}
            targetExists={targetExists}
            mode={mode}
            secure={secure}
            suppressMissingLoginBadge={suppressMissingLoginBadge}
          />
        </div>
        {onRerollValue ? (
          <button
            type="button"
            className="w3a-input-action-trigger"
            aria-label={rerollValueLabel}
            title={rerollValueLabel}
            onClick={onRerollValue}
            disabled={waiting || rerollValueDisabled}
          >
            <RerollValueIcon />
          </button>
        ) : showAccountOptions ? (
          <div
            ref={accountMenuRef}
            className={`w3a-account-menu${accountMenuOpen ? ' is-open' : ''}`}
          >
            <button
              type="button"
              className="w3a-account-menu-trigger"
              aria-label="Saved accounts"
              aria-haspopup="listbox"
              aria-expanded={accountMenuOpen}
              aria-controls={menuId}
              onClick={() => setAccountMenuOpen((open) => !open)}
              disabled={waiting}
            >
              <AccountDropdownArrow />
            </button>
            {accountMenuOpen ? (
              <div id={menuId} className="w3a-account-menu-popover" role="listbox">
                {accountGroups.map((group) => (
                  <div key={group.label} className="w3a-account-menu-group">
                    <div className="w3a-account-menu-group-label">{group.label}</div>
                    {group.accounts.map((account) => {
                      const selected = accountOptionSelected(account, value);
                      return (
                        <button
                          key={`${account.walletId}:${account.authMethod}:${account.displayName}`}
                          type="button"
                          role="option"
                          aria-selected={selected}
                          className={`w3a-account-menu-option${selected ? ' is-selected' : ''}`}
                          title={accountOptionTitle(account)}
                          onClick={() => {
                            onChange(account.walletId);
                            setAccountMenuOpen(false);
                          }}
                        >
                          <span className="w3a-account-menu-check" aria-hidden="true" />
                          <span className="w3a-account-menu-account">
                            <span className="w3a-account-menu-account-primary">
                              {account.displayName}
                            </span>
                            {shouldShowAccountWalletId(account) ? (
                              <span className="w3a-account-menu-account-secondary">
                                {account.walletId}
                              </span>
                            ) : null}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
};

export default PasskeyInput;
