import React from 'react';

export interface DashboardScopeOption {
  value: string;
  label: string;
  description: string;
}

interface ScopePickerProps {
  label: string;
  options: readonly DashboardScopeOption[];
  values: string[];
  onChange(next: string[]): void;
  disabled?: boolean;
  variant?: 'picker' | 'segmented';
  addLabel?: string;
  emptyLabel?: string;
  placeholderLabel?: string;
}

function dedupeScopes(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of Array.isArray(values) ? values : []) {
    const value = String(raw || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

export function ScopePicker(props: ScopePickerProps): React.JSX.Element {
  const {
    label,
    options,
    values,
    onChange,
    disabled = false,
    variant = 'picker',
    addLabel = 'Add scope',
    emptyLabel = 'No scopes selected.',
    placeholderLabel = 'Select a scope',
  } = props;
  const selected = dedupeScopes(values);
  const knownValues = new Set(options.map((option) => option.value));
  const availableOptions = options.filter((option) => !selected.includes(option.value));

  if (variant === 'segmented') {
    return (
      <div className="dashboard-scope-picker dashboard-scope-picker--segmented">
        <div className="dashboard-scope-picker__header">
          <span>{label}</span>
        </div>

        <div className="dashboard-scope-picker__segments" role="group" aria-label={`${label} toggles`}>
          {options.map((option) => {
            const active = selected.includes(option.value);
            return (
              <button
                key={option.value}
                type="button"
                className={[
                  'dashboard-scope-picker__segment',
                  active ? 'dashboard-scope-picker__segment--active' : '',
                ]
                  .filter(Boolean)
                  .join(' ')}
                aria-pressed={active}
                disabled={disabled}
                onClick={() =>
                  onChange(
                    active
                      ? selected.filter((entry) => entry !== option.value)
                      : [...selected, option.value],
                  )
                }
              >
                <strong>{option.value}</strong>
                <span>{option.description}</span>
              </button>
            );
          })}
        </div>

        {selected.length === 0 ? <p className="dashboard-scope-picker__empty">{emptyLabel}</p> : null}
      </div>
    );
  }

  return (
    <div className="dashboard-scope-picker">
      <div className="dashboard-scope-picker__header">
        <span>{label}</span>
      </div>

      <label className="dashboard-form-field">
        {addLabel ? <span>{addLabel}</span> : null}
        <select
          className="dashboard-input dashboard-scope-picker__select"
          value=""
          disabled={disabled || availableOptions.length === 0}
          aria-label={`${label} dropdown`}
          onChange={(event) => {
            const nextValue = String(event.target.value || '').trim();
            if (!nextValue) return;
            onChange([...selected, nextValue]);
          }}
        >
          <option value="">
            {availableOptions.length > 0
              ? placeholderLabel
              : 'All available scopes selected'}
          </option>
          {options.map((option) => (
            <option
              key={option.value}
              value={option.value}
              disabled={selected.includes(option.value)}
            >
              {`${option.value} - ${option.label}`}
            </option>
          ))}
        </select>
      </label>

      <div className="dashboard-scope-picker__chips" aria-label={`${label} selected scopes`}>
        {selected.length > 0 ? (
          selected.map((scope) => {
            const option = options.find((entry) => entry.value === scope);
            return (
              <span
                key={scope}
                className={[
                  'dashboard-scope-picker__chip',
                  knownValues.has(scope) ? '' : 'dashboard-scope-picker__chip--custom',
                ]
                  .filter(Boolean)
                  .join(' ')}
                title={option?.description || scope}
              >
                <span className="dashboard-scope-picker__chip-label">{scope}</span>
                <button
                  type="button"
                  className="dashboard-scope-picker__chip-remove"
                  onClick={() => onChange(selected.filter((entry) => entry !== scope))}
                  disabled={disabled}
                  aria-label={`Remove scope ${scope}`}
                >
                  x
                </button>
              </span>
            );
          })
        ) : (
          <p className="dashboard-scope-picker__empty">{emptyLabel}</p>
        )}
      </div>
    </div>
  );
}

export default ScopePicker;
