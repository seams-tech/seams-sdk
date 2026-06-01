import React from 'react';
import type { StoredAccountOption } from '@/react/types';
import { AuthMenuMode } from '../authMenuTypes';
import { AccountExistsBadge } from './AccountExistsBadge';
import { usePostfixPosition } from './usePostfixPosition';

export interface PasskeyInputProps {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  postfixText?: string;
  isUsingExistingAccount?: boolean;
  accountExists?: boolean;
  accountOptions?: StoredAccountOption[];
  onProceed: () => void;
  /** Current signup mode for status badge */
  mode?: AuthMenuMode;
  /** Whether the current context is secure (HTTPS) */
  secure?: boolean;
  /** Whether the parent flow is waiting on passkey resolution */
  waiting?: boolean;
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

function groupAccountOptions(accountOptions?: StoredAccountOption[]): AccountOptionGroup[] {
  const uniqueAccounts = new Map<string, StoredAccountOption>();
  for (const option of accountOptions ?? []) {
    const nearAccountId = String(option.nearAccountId || '').trim();
    if (!nearAccountId) continue;
    const authMethodKey = option.authMethod || 'passkey';
    uniqueAccounts.set(`${nearAccountId}:${authMethodKey}`, {
      nearAccountId,
      ...(typeof option.signerSlot === 'number' ? { signerSlot: option.signerSlot } : {}),
      ...(option.authMethod ? { authMethod: option.authMethod } : {}),
    });
  }

  const sortedAccounts = [...uniqueAccounts.values()].sort((a, b) =>
    a.nearAccountId.localeCompare(b.nearAccountId),
  );
  const passkeyAccounts = sortedAccounts.filter((option) => option.authMethod !== 'email_otp');
  const emailOtpAccounts = sortedAccounts.filter((option) => option.authMethod === 'email_otp');
  const groups: AccountOptionGroup[] = [
    { label: 'Passkey', accounts: passkeyAccounts },
    { label: 'Email OTP', accounts: emailOtpAccounts },
  ];
  return groups.filter((group) => group.accounts.length > 0);
}

export const PasskeyInput: React.FC<PasskeyInputProps> = ({
  value,
  onChange,
  placeholder,
  postfixText,
  isUsingExistingAccount,
  accountExists,
  accountOptions,
  onProceed,
  mode,
  secure,
  waiting = false,
}: PasskeyInputProps) => {
  const statusId = React.useId();
  const inputId = React.useId();
  const menuId = React.useId();
  const { bindInput, bindPostfix } = usePostfixPosition({ inputValue: value, gap: 1 });
  const showAccountOptions = mode === AuthMenuMode.Login && !!accountOptions?.length;
  const accountGroups = React.useMemo(() => groupAccountOptions(accountOptions), [accountOptions]);
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
            value={value}
            onChange={(e) => {
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
          />
          {postfixText && value.length > 0 && (
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
            isUsingExistingAccount={isUsingExistingAccount}
            accountExists={accountExists}
            mode={mode}
            secure={secure}
          />
        </div>
        {showAccountOptions ? (
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
                      const selected = account.nearAccountId.toLowerCase() === value.toLowerCase();
                      return (
                        <button
                          key={`${account.nearAccountId}:${account.authMethod || 'passkey'}`}
                          type="button"
                          role="option"
                          aria-selected={selected}
                          className={`w3a-account-menu-option${selected ? ' is-selected' : ''}`}
                          title={account.nearAccountId}
                          onClick={() => {
                            onChange(account.nearAccountId);
                            setAccountMenuOpen(false);
                          }}
                        >
                          <span className="w3a-account-menu-check" aria-hidden="true" />
                          <span className="w3a-account-menu-account">{account.nearAccountId}</span>
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
