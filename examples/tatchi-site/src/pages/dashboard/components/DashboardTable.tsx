import React from 'react';
import clsx from 'clsx';

export type DashboardTableTone = 'neutral' | 'success' | 'warning' | 'danger';
export type DashboardTableColumnSize = number | string;
export type DashboardTableColumns = number | readonly DashboardTableColumnSize[];

export interface DashboardTableProps {
  ariaLabel: string;
  columns: DashboardTableColumns;
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableIntroProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableHeaderProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableHeaderCellProps {
  className?: string;
  span?: number;
  children: React.ReactNode;
}

export interface DashboardTableRowProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableCellProps {
  className?: string;
  title?: string;
  truncate?: boolean;
  muted?: boolean;
  align?: 'start' | 'center' | 'end';
  span?: number;
  children: React.ReactNode;
}

export interface DashboardTableStateProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableFooterProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableBadgeProps {
  className?: string;
  tone?: DashboardTableTone;
  children: React.ReactNode;
}

export interface DashboardTableStatusProps {
  className?: string;
  tone?: DashboardTableTone;
  children: React.ReactNode;
}

export interface DashboardTableActionGroupProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableActionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  tone?: 'neutral' | 'danger';
}

export interface DashboardTableDetailsPanelProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableDetailsGridProps {
  className?: string;
  children: React.ReactNode;
}

export interface DashboardTableDetailsItemProps {
  className?: string;
  label: React.ReactNode;
  children: React.ReactNode;
}

function buildTableTemplate(columns: DashboardTableColumns): string {
  if (typeof columns === 'number') {
    return `repeat(${Math.max(1, columns)}, minmax(0, 1fr))`;
  }
  if (columns.length === 0) return 'minmax(0, 1fr)';
  return columns
    .map((size) => {
      const normalized = typeof size === 'number' ? `${size}fr` : String(size).trim();
      return `minmax(0, ${normalized})`;
    })
    .join(' ');
}

function buildTableStyle(columns: DashboardTableColumns): React.CSSProperties {
  return {
    '--dashboard-data-table-columns': buildTableTemplate(columns),
  } as React.CSSProperties;
}

function buildTableItemStyle(span?: number): React.CSSProperties | undefined {
  if (!span || span <= 1) return undefined;
  return { gridColumn: `span ${span}` };
}

export function dashboardTableColumns(
  ...sizes: DashboardTableColumnSize[]
): readonly DashboardTableColumnSize[] {
  return sizes.length === 0 ? [1] : sizes;
}

export function dashboardTableToneClassName(
  baseClassName: string,
  tone: DashboardTableTone = 'neutral',
): string {
  return `${baseClassName} ${baseClassName}--${tone}`;
}

export function DashboardTable(props: DashboardTableProps): React.JSX.Element {
  const { ariaLabel, columns, className, children } = props;
  return (
    <section
      className={clsx('dashboard-data-table', className)}
      aria-label={ariaLabel}
      role="table"
      style={buildTableStyle(columns)}
    >
      {children}
    </section>
  );
}

export function DashboardTableIntro(props: DashboardTableIntroProps): React.JSX.Element {
  const { className, children } = props;
  return <div className={clsx('dashboard-data-table__intro', className)}>{children}</div>;
}

export function DashboardTableHeader(props: DashboardTableHeaderProps): React.JSX.Element {
  const { className, children } = props;
  return (
    <div className={clsx('dashboard-data-table__header', className)} role="row">
      {children}
    </div>
  );
}

export function DashboardTableHeaderCell(props: DashboardTableHeaderCellProps): React.JSX.Element {
  const { className, span, children } = props;
  return (
    <span
      className={clsx('dashboard-data-table__header-cell', className)}
      role="columnheader"
      style={buildTableItemStyle(span)}
    >
      {children}
    </span>
  );
}

export function DashboardTableRow(props: DashboardTableRowProps): React.JSX.Element {
  const { className, children } = props;
  return (
    <div className={clsx('dashboard-data-table__row', className)} role="row">
      {children}
    </div>
  );
}

export function DashboardTableCell(props: DashboardTableCellProps): React.JSX.Element {
  const {
    className,
    title,
    truncate = false,
    muted = false,
    align = 'start',
    span,
    children,
  } = props;
  return (
    <div
      className={clsx(
        'dashboard-data-table__cell',
        truncate && 'dashboard-data-table__cell--truncate',
        muted && 'dashboard-data-table__cell--muted',
        align === 'center' && 'dashboard-data-table__cell--center',
        align === 'end' && 'dashboard-data-table__cell--end',
        className,
      )}
      role="cell"
      title={title}
      style={buildTableItemStyle(span)}
    >
      {children}
    </div>
  );
}

export function DashboardTableState(props: DashboardTableStateProps): React.JSX.Element {
  const { className, children } = props;
  return <p className={clsx('dashboard-data-table__state', className)}>{children}</p>;
}

export function DashboardTableFooter(props: DashboardTableFooterProps): React.JSX.Element {
  const { className, children } = props;
  return <div className={clsx('dashboard-data-table__footer', className)}>{children}</div>;
}

export function DashboardTableBadge(props: DashboardTableBadgeProps): React.JSX.Element {
  const { className, tone = 'neutral', children } = props;
  return (
    <span
      className={clsx(dashboardTableToneClassName('dashboard-data-table__badge', tone), className)}
    >
      {children}
    </span>
  );
}

export function DashboardTableStatus(props: DashboardTableStatusProps): React.JSX.Element {
  const { className, tone = 'neutral', children } = props;
  return (
    <span
      className={clsx(dashboardTableToneClassName('dashboard-data-table__status', tone), className)}
    >
      {children}
    </span>
  );
}

export function DashboardTableActionGroup(
  props: DashboardTableActionGroupProps,
): React.JSX.Element {
  const { className, children } = props;
  return <div className={clsx('dashboard-data-table__actions', className)}>{children}</div>;
}

export function DashboardTableActionButton(
  props: DashboardTableActionButtonProps,
): React.JSX.Element {
  const { className, tone = 'neutral', type = 'button', children, ...rest } = props;
  return (
    <button
      {...rest}
      type={type}
      className={clsx(
        'dashboard-data-table__action-button',
        tone === 'danger' && 'dashboard-data-table__action-button--danger',
        className,
      )}
    >
      {children}
    </button>
  );
}

export function DashboardTableDetailsPanel(
  props: DashboardTableDetailsPanelProps,
): React.JSX.Element {
  const { className, children } = props;
  return <div className={clsx('dashboard-data-table__details-panel', className)}>{children}</div>;
}

export function DashboardTableDetailsGrid(
  props: DashboardTableDetailsGridProps,
): React.JSX.Element {
  const { className, children } = props;
  return <div className={clsx('dashboard-data-table__details-grid', className)}>{children}</div>;
}

export function DashboardTableDetailsItem(
  props: DashboardTableDetailsItemProps,
): React.JSX.Element {
  const { className, label, children } = props;
  return (
    <div className={clsx('dashboard-data-table__details-item', className)}>
      <span className="dashboard-data-table__details-label">{label}</span>
      {children}
    </div>
  );
}
