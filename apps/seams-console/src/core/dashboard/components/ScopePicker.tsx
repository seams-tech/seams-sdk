import React from 'react';

export interface DashboardScopeOption<Value extends string = string> {
  value: Value;
  label: string;
  description: string;
}

interface ScopePickerProps<Value extends string = string> {
  label: string;
  options: readonly DashboardScopeOption<Value>[];
  values: readonly Value[];
  onChange(next: Value[]): void;
  disabled?: boolean;
  variant?: 'picker' | 'segmented';
  addLabel?: string;
  emptyLabel?: string;
  placeholderLabel?: string;
}

function dedupeScopes<Value extends string>(values: readonly Value[]): Value[] {
  const out: Value[] = [];
  const seen = new Set<string>();
  for (const value of Array.isArray(values) ? values : []) {
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

export function ScopePicker<Value extends string = string>(
  props: ScopePickerProps<Value>,
): React.JSX.Element {
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
            const stateLabel = active ? 'On' : 'Off';
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
                aria-label={`${option.value} ${stateLabel}: ${option.description}`}
                disabled={disabled}
                onClick={() =>
                  onChange(
                    active
                      ? selected.filter((entry) => entry !== option.value)
                      : [...selected, option.value],
                  )
                }
              >
                <span className="dashboard-scope-picker__segment-top">
                  <strong>{option.value}</strong>
                  <span
                    className={[
                      'dashboard-scope-picker__segment-state',
                      active ? 'dashboard-scope-picker__segment-state--active' : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                  >
                    {stateLabel}
                  </span>
                </span>
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
            const nextOption = options.find((option) => option.value === nextValue);
            if (!nextOption) return;
            onChange([...selected, nextOption.value]);
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
