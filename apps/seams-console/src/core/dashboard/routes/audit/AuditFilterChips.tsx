import React from 'react';
import { PlusIcon, XIcon } from '../../icons/SidebarIcons';

export interface AuditFilterOption {
  value: string;
  label: string;
}

export interface AuditFilterDefinition {
  id: string;
  label: string;
  value: string;
  options: readonly AuditFilterOption[];
}

interface AuditFilterChipsProps {
  filters: readonly AuditFilterDefinition[];
  onChange(id: string, value: string): void;
  onClearAll(): void;
}

function AuditFilterChip(props: {
  filter: AuditFilterDefinition;
  onChange(value: string): void;
}): React.JSX.Element {
  const { filter, onChange } = props;
  const [open, setOpen] = React.useState<boolean>(false);
  const rootRef = React.useRef<HTMLDivElement | null>(null);
  const active = Boolean(filter.value);
  const selected = filter.options.find((option) => option.value === filter.value);

  React.useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  return (
    <div
      className={[
        'dashboard-audit-chip',
        active ? 'dashboard-audit-chip--active' : '',
        open ? 'dashboard-audit-chip--open' : '',
      ]
        .filter(Boolean)
        .join(' ')}
      ref={rootRef}
    >
      <button
        type="button"
        className="dashboard-audit-chip__trigger"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        {active ? null : (
          <PlusIcon size={13} strokeWidth={2} className="dashboard-audit-chip__plus" />
        )}
        <span className="dashboard-audit-chip__text">
          {filter.label}
          {active ? (
            <>
              <span className="dashboard-audit-chip__separator">:</span>
              <span className="dashboard-audit-chip__value">
                {selected ? selected.label : filter.value}
              </span>
            </>
          ) : null}
        </span>
      </button>

      {/* The clear control is a sibling button, not nested inside the
          trigger: a button inside a button is invalid and browsers drop the
          inner one from the accessibility tree. */}
      {active ? (
        <button
          type="button"
          className="dashboard-audit-chip__clear"
          aria-label={`Clear ${filter.label.toLowerCase()} filter`}
          onClick={() => {
            setOpen(false);
            onChange('');
          }}
        >
          <XIcon size={12} strokeWidth={2.25} />
        </button>
      ) : null}

      {open ? (
        <div className="dashboard-context-menu dashboard-audit-chip__menu" role="menu">
          <button
            type="button"
            role="menuitemradio"
            aria-checked={!active}
            className={['dashboard-context-menu__item', !active ? 'is-selected' : '']
              .filter(Boolean)
              .join(' ')}
            onClick={() => {
              setOpen(false);
              onChange('');
            }}
          >
            All
          </button>
          {filter.options.map((option) => (
            <button
              key={option.value}
              type="button"
              role="menuitemradio"
              aria-checked={option.value === filter.value}
              className={[
                'dashboard-context-menu__item',
                option.value === filter.value ? 'is-selected' : '',
              ]
                .filter(Boolean)
                .join(' ')}
              onClick={() => {
                setOpen(false);
                onChange(option.value);
              }}
            >
              {option.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/* Additive filter row: each dimension starts as a "+ Name" affordance and
   only takes up chip width once it actually constrains the query. */
export function AuditFilterChips(props: AuditFilterChipsProps): React.JSX.Element {
  const { filters, onChange, onClearAll } = props;
  const anyActive = filters.some((filter) => Boolean(filter.value));

  return (
    <div className="dashboard-audit-chips" role="group" aria-label="Audit event filters">
      {filters.map((filter) => (
        <AuditFilterChip
          key={filter.id}
          filter={filter}
          onChange={(value) => onChange(filter.id, value)}
        />
      ))}
      {anyActive ? (
        <button
          type="button"
          className="dashboard-audit-chips__clear"
          aria-label="Clear all filters"
          title="Clear all filters"
          onClick={onClearAll}
        >
          <XIcon size={14} strokeWidth={2} />
        </button>
      ) : null}
    </div>
  );
}
