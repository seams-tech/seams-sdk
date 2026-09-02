import React from 'react';
import { formatDashboardTimestamp } from '../../utils/timestamps';
import {
  CalendarIcon,
  ChevronDownIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
} from '../../icons/SidebarIcons';
import {
  AUDIT_RANGE_PRESETS,
  auditActivityAxis,
  auditRangeLabel,
  auditRangeSpanPreset,
  formatUtcOffsetLabel,
  fromDateTimeLocalInput,
  toDateTimeLocalInput,
  type AuditActivityBin,
  type AuditRangePresetId,
  type AuditTimeRange,
} from './auditActivity';

interface AuditActivityChartProps {
  bins: readonly AuditActivityBin[];
  range: AuditTimeRange;
  nowMs: number;
  loading: boolean;
  selection: AuditTimeRange | null;
  canStepForward: boolean;
  onPresetChange(next: AuditRangePresetId): void;
  onStepRange(direction: -1 | 1): void;
  onSelectionChange(next: AuditTimeRange | null): void;
  onFocusSelection(): void;
  onJumpToTimestamp(atMs: number): void;
}

/* A drag on the plot reads as a fraction of its width rather than as pixels,
   so the same handler serves whatever width the card is laid out at. */
function readPlotFraction(element: HTMLElement, clientX: number): number {
  const bounds = element.getBoundingClientRect();
  if (bounds.width <= 0) return 0;
  return Math.min(1, Math.max(0, (clientX - bounds.left) / bounds.width));
}

function useDismissable(open: boolean, onDismiss: () => void) {
  const rootRef = React.useRef<HTMLDivElement | null>(null);
  React.useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) onDismiss();
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onDismiss();
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open, onDismiss]);
  return rootRef;
}

function AuditRangePicker(props: {
  range: AuditTimeRange;
  nowMs: number;
  canStepForward: boolean;
  onPresetChange(next: AuditRangePresetId): void;
  onStepRange(direction: -1 | 1): void;
}): React.JSX.Element {
  const { range, nowMs, canStepForward, onPresetChange, onStepRange } = props;
  const [open, setOpen] = React.useState<boolean>(false);
  const dismiss = React.useCallback(() => setOpen(false), []);
  const rootRef = useDismissable(open, dismiss);
  const activePresetId = auditRangeSpanPreset(range)?.id || null;

  return (
    <div className="dashboard-audit-range" ref={rootRef}>
      <button
        type="button"
        className="dashboard-audit-range__step"
        aria-label="Previous period"
        onClick={() => onStepRange(-1)}
      >
        <ChevronLeftIcon size={15} strokeWidth={1.75} />
      </button>
      <span className="dashboard-audit-range__divider" aria-hidden="true" />
      <button
        type="button"
        className="dashboard-audit-range__preset"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((current) => !current)}
      >
        <CalendarIcon size={15} strokeWidth={1.75} />
        <span className="dashboard-audit-range__label">
          {auditRangeLabel(range, nowMs)}
          <span className="dashboard-audit-range__zone"> · {formatUtcOffsetLabel(nowMs)}</span>
        </span>
        <ChevronDownIcon size={14} strokeWidth={1.75} />
      </button>
      <span className="dashboard-audit-range__divider" aria-hidden="true" />
      <button
        type="button"
        className="dashboard-audit-range__step"
        aria-label="Next period"
        disabled={!canStepForward}
        onClick={() => onStepRange(1)}
      >
        <ChevronRightIcon size={15} strokeWidth={1.75} />
      </button>

      {open ? (
        <div className="dashboard-context-menu dashboard-audit-range__menu" role="menu">
          {AUDIT_RANGE_PRESETS.map((entry) => (
            <button
              key={entry.id}
              type="button"
              role="menuitemradio"
              aria-checked={entry.id === activePresetId}
              className={[
                'dashboard-context-menu__item',
                entry.id === activePresetId ? 'is-selected' : '',
              ]
                .filter(Boolean)
                .join(' ')}
              onClick={() => {
                setOpen(false);
                onPresetChange(entry.id);
              }}
            >
              {entry.label}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function AuditJumpControl(props: {
  range: AuditTimeRange;
  nowMs: number;
  onJumpToTimestamp(atMs: number): void;
}): React.JSX.Element {
  const { range, nowMs, onJumpToTimestamp } = props;
  const [open, setOpen] = React.useState<boolean>(false);
  const [value, setValue] = React.useState<string>('');
  const dismiss = React.useCallback(() => setOpen(false), []);
  const rootRef = useDismissable(open, dismiss);

  return (
    <div className="dashboard-audit-jump" ref={rootRef}>
      <button
        type="button"
        className="dashboard-pagination-button dashboard-pagination-button--primary"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() =>
          setOpen((current) => {
            if (!current) setValue(toDateTimeLocalInput(range.toMs));
            return !current;
          })
        }
      >
        Jump to timestamp
      </button>
      {open ? (
        <form
          className="dashboard-audit-jump__panel"
          onSubmit={(event) => {
            event.preventDefault();
            const atMs = fromDateTimeLocalInput(value);
            if (atMs === null) return;
            setOpen(false);
            onJumpToTimestamp(Math.min(atMs, nowMs));
          }}
        >
          <label className="dashboard-form-field">
            <span>Centre the window on</span>
            <input
              className="dashboard-input"
              type="datetime-local"
              value={value}
              max={toDateTimeLocalInput(nowMs)}
              onChange={(event) => setValue(event.target.value)}
            />
          </label>
          <div className="dashboard-audit-jump__actions">
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={() => setOpen(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="dashboard-pagination-button dashboard-pagination-button--primary"
              disabled={fromDateTimeLocalInput(value) === null}
            >
              Jump
            </button>
          </div>
        </form>
      ) : null}
    </div>
  );
}

/* Event volume over the selected window. Dragging across the plot marks a
   sub-window that "Focus to selection" then narrows the whole page to.

   The plot itself is exposed as an image with a text summary rather than as
   a keyboard widget: the same narrowing is reachable without a pointer
   through the period presets and "Jump to timestamp", so a drag surface adds
   no capability a keyboard user would otherwise lose. */
export function AuditActivityChart(props: AuditActivityChartProps): React.JSX.Element {
  const {
    bins,
    range,
    nowMs,
    loading,
    selection,
    canStepForward,
    onPresetChange,
    onStepRange,
    onSelectionChange,
    onFocusSelection,
    onJumpToTimestamp,
  } = props;

  const plotRef = React.useRef<HTMLDivElement | null>(null);
  const [dragFractions, setDragFractions] = React.useState<[number, number] | null>(null);
  const axis = React.useMemo(() => auditActivityAxis(bins), [bins]);
  const span = Math.max(1, range.toMs - range.fromMs);
  const total = bins.reduce((current, bin) => current + bin.total, 0);
  const failures = bins.reduce((current, bin) => current + bin.failures, 0);

  const fractionToMs = React.useCallback(
    (fraction: number) => range.fromMs + fraction * span,
    [range.fromMs, span],
  );

  const commitDrag = React.useCallback(
    (fractions: [number, number]) => {
      const [start, end] = fractions;
      /* A click with no travel is a dismissal, not a one-pixel window. */
      if (Math.abs(end - start) < 0.01) {
        onSelectionChange(null);
        return;
      }
      const fromMs = fractionToMs(Math.min(start, end));
      const toMs = fractionToMs(Math.max(start, end));
      onSelectionChange({ fromMs, toMs });
    },
    [fractionToMs, onSelectionChange],
  );

  const selectionBand = React.useMemo(() => {
    const active = dragFractions
      ? {
          left: Math.min(dragFractions[0], dragFractions[1]),
          right: Math.max(dragFractions[0], dragFractions[1]),
        }
      : selection
        ? {
            left: Math.min(1, Math.max(0, (selection.fromMs - range.fromMs) / span)),
            right: Math.min(1, Math.max(0, (selection.toMs - range.fromMs) / span)),
          }
        : null;
    if (!active || active.right - active.left <= 0) return null;
    return {
      left: `${active.left * 100}%`,
      width: `${(active.right - active.left) * 100}%`,
    };
  }, [dragFractions, range.fromMs, selection, span]);

  return (
    <section className="dashboard-audit-activity" aria-label="Audit event activity">
      <div className="dashboard-audit-activity__plot-row">
        {/* Ticks are positioned off the same fraction as the gridlines rather
            than distributed by the flexbox, so a label always sits on the
            line it names. */}
        <div className="dashboard-audit-activity__axis" aria-hidden="true">
          {axis.ticks.map((tick) => (
            <span
              key={tick}
              className="dashboard-audit-activity__axis-tick"
              style={{ bottom: `${(tick / axis.max) * 100}%` }}
            >
              {tick}
            </span>
          ))}
        </div>

        <div
          className="dashboard-audit-activity__plot"
          ref={plotRef}
          role="img"
          aria-label={
            loading
              ? 'Loading audit event activity'
              : `${total} audit ${total === 1 ? 'event' : 'events'}${
                  failures ? `, ${failures} failed` : ''
                } between ${formatDashboardTimestamp(range.fromMs)} and ${formatDashboardTimestamp(
                  range.toMs,
                )}`
          }
          onPointerDown={(event) => {
            if (event.button !== 0) return;
            const host = plotRef.current;
            if (!host) return;
            host.setPointerCapture(event.pointerId);
            const fraction = readPlotFraction(host, event.clientX);
            setDragFractions([fraction, fraction]);
          }}
          onPointerMove={(event) => {
            if (!dragFractions) return;
            const host = plotRef.current;
            if (!host) return;
            const fraction = readPlotFraction(host, event.clientX);
            setDragFractions([dragFractions[0], fraction]);
          }}
          onPointerUp={(event) => {
            if (!dragFractions) return;
            const host = plotRef.current;
            if (host?.hasPointerCapture(event.pointerId)) {
              host.releasePointerCapture(event.pointerId);
            }
            const fractions = dragFractions;
            setDragFractions(null);
            commitDrag(fractions);
          }}
          onPointerCancel={() => setDragFractions(null)}
        >
          {axis.ticks.map((tick) => (
            <span
              key={tick}
              className="dashboard-audit-activity__gridline"
              style={{ bottom: `${(tick / axis.max) * 100}%` }}
              aria-hidden="true"
            />
          ))}

          {selectionBand ? (
            <span
              className="dashboard-audit-activity__band"
              style={{ left: selectionBand.left, width: selectionBand.width }}
              aria-hidden="true"
            />
          ) : null}

          <div className="dashboard-audit-activity__bars">
            {bins.map((bin) => {
              const height = axis.max > 0 ? (bin.total / axis.max) * 100 : 0;
              const failureShare = bin.total > 0 ? (bin.failures / bin.total) * 100 : 0;
              return (
                <span
                  key={bin.startMs}
                  className="dashboard-audit-activity__bar"
                  title={`${formatDashboardTimestamp(bin.startMs)} — ${bin.total} ${
                    bin.total === 1 ? 'event' : 'events'
                  }${bin.failures ? `, ${bin.failures} failed` : ''}`}
                >
                  {/* An empty bucket paints nothing at all: a minimum-height
                      seat on every bar would draw a continuous line along the
                      baseline and read as activity everywhere. */}
                  {bin.total > 0 ? (
                    <span
                      className="dashboard-audit-activity__bar-fill"
                      style={{ height: `${height}%` }}
                    >
                      {bin.failures ? (
                        <span
                          className="dashboard-audit-activity__bar-failures"
                          style={{ height: `${failureShare}%` }}
                        />
                      ) : null}
                    </span>
                  ) : null}
                </span>
              );
            })}
          </div>
        </div>
      </div>

      <div className="dashboard-audit-activity__scale">
        <span>{formatDashboardTimestamp(range.fromMs)}</span>
        <span>{formatDashboardTimestamp(range.toMs)}</span>
      </div>

      <div className="dashboard-audit-activity__footer">
        <AuditRangePicker
          range={range}
          nowMs={nowMs}
          canStepForward={canStepForward}
          onPresetChange={onPresetChange}
          onStepRange={onStepRange}
        />
        <div className="dashboard-audit-activity__footer-actions">
          <AuditJumpControl range={range} nowMs={nowMs} onJumpToTimestamp={onJumpToTimestamp} />
          <button
            type="button"
            className="dashboard-pagination-button dashboard-pagination-button--secondary"
            disabled={!selection}
            onClick={onFocusSelection}
          >
            Focus to selection
          </button>
        </div>
      </div>
    </section>
  );
}
