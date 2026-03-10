import React from 'react';
import clsx from 'clsx';

export type DashboardTableTone = 'neutral' | 'success' | 'warning' | 'danger';
export type DashboardTableColumnSize = number | string;
export type DashboardTableColumns = number | readonly DashboardTableColumnSize[];

const DEFAULT_DASHBOARD_TABLE_ROWS_PER_PAGE_OPTIONS = [10, 25, 50] as const;
const DEFAULT_DASHBOARD_TABLE_JUMP_PAGES = [10, 25, 50] as const;

export interface DashboardTableProps {
  ariaLabel: string;
  columns: DashboardTableColumns;
  className?: string;
  pagination?: DashboardTablePaginationConfig;
  children: React.ReactNode;
}

export interface DashboardTablePaginationConfig {
  page: number;
  totalPages: number;
  totalRows: number;
  rowsPerPage: number;
  onPageChange: (page: number) => void;
  className?: string;
  disabled?: boolean;
  itemLabel?: string;
  itemLabelPlural?: string;
  quickJumpPages?: readonly number[];
  quickJumpThreshold?: number;
  rowsPerPageOptions?: readonly number[];
  showJumpToPageInput?: boolean;
  onRowsPerPageChange?: (rowsPerPage: number) => void;
}

export interface DashboardTablePaginationOptions {
  initialPage?: number;
  initialRowsPerPage?: number;
  disabled?: boolean;
  itemLabel?: string;
  itemLabelPlural?: string;
  quickJumpPages?: readonly number[];
  quickJumpThreshold?: number;
  rowsPerPageOptions?: readonly number[];
  showJumpToPageInput?: boolean;
}

export interface DashboardTablePaginationResult<T> {
  page: number;
  rows: readonly T[];
  rowsPerPage: number;
  setPage: (page: number) => void;
  setRowsPerPage: (rowsPerPage: number) => void;
  totalPages: number;
  totalRows: number;
  pagination: DashboardTablePaginationConfig;
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

interface DashboardTablePaginationJumpTarget {
  label: string;
  page: number;
}

function clampNumber(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, value));
}

function normalizeRowsPerPageOptions(options?: readonly number[]): number[] {
  const source = options?.length ? options : DEFAULT_DASHBOARD_TABLE_ROWS_PER_PAGE_OPTIONS;
  const normalized: number[] = [];
  const seen = new Set<number>();
  for (const option of source) {
    const pageSize = Math.max(1, Math.floor(Number(option) || 0));
    if (seen.has(pageSize)) continue;
    seen.add(pageSize);
    normalized.push(pageSize);
  }
  return normalized.length > 0 ? normalized : [DEFAULT_DASHBOARD_TABLE_ROWS_PER_PAGE_OPTIONS[0]];
}

function normalizeRowsPerPageValue(value: number, options: readonly number[]): number {
  const normalized = Math.max(1, Math.floor(Number(value) || 0));
  return options.includes(normalized) ? normalized : options[0];
}

function buildPaginationJumpTargets(
  totalPages: number,
  quickJumpPages?: readonly number[],
  quickJumpThreshold?: number,
): DashboardTablePaginationJumpTarget[] {
  const minimumPageCount = Math.max(1, Math.floor(Number(quickJumpThreshold) || 10));
  if (totalPages <= minimumPageCount) return [];
  const targets: DashboardTablePaginationJumpTarget[] = [];
  const seen = new Set<number>();
  const normalizedTargets = quickJumpPages?.length
    ? quickJumpPages
    : DEFAULT_DASHBOARD_TABLE_JUMP_PAGES;
  for (const rawTarget of normalizedTargets) {
    const targetPage = Math.max(1, Math.floor(Number(rawTarget) || 0));
    if (targetPage <= 1 || targetPage >= totalPages || seen.has(targetPage)) continue;
    seen.add(targetPage);
    targets.push({ label: String(targetPage), page: targetPage });
  }
  if (!seen.has(totalPages)) {
    targets.push({ label: 'Last', page: totalPages });
  }
  return targets;
}

function buildPaginationSummary(config: DashboardTablePaginationConfig): string {
  const singular = config.itemLabel || 'row';
  const plural = config.itemLabelPlural || `${singular}s`;
  if (config.totalRows <= 0) return `Showing 0 of 0 ${plural}`;
  const rangeStart = (config.page - 1) * config.rowsPerPage + 1;
  const rangeEnd = Math.min(config.totalRows, config.page * config.rowsPerPage);
  return `Showing ${rangeStart}-${rangeEnd} of ${config.totalRows} ${
    config.totalRows === 1 ? singular : plural
  }`;
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

export function useDashboardTablePagination<T>(
  rows: readonly T[],
  options: DashboardTablePaginationOptions = {},
): DashboardTablePaginationResult<T> {
  const rowsPerPageOptions = React.useMemo(
    () => normalizeRowsPerPageOptions(options.rowsPerPageOptions),
    [options.rowsPerPageOptions],
  );
  const [page, setPageState] = React.useState<number>(Math.max(1, options.initialPage || 1));
  const [rowsPerPage, setRowsPerPageState] = React.useState<number>(() =>
    normalizeRowsPerPageValue(
      options.initialRowsPerPage || rowsPerPageOptions[0],
      rowsPerPageOptions,
    ),
  );
  const totalRows = rows.length;
  const totalPages = Math.max(1, Math.ceil(totalRows / rowsPerPage));

  React.useEffect(() => {
    setPageState((current) => clampNumber(current, 1, totalPages));
  }, [totalPages]);

  React.useEffect(() => {
    setRowsPerPageState((current) => normalizeRowsPerPageValue(current, rowsPerPageOptions));
  }, [rowsPerPageOptions]);

  const setPage = React.useCallback(
    (nextPage: number) => {
      setPageState(clampNumber(Math.floor(Number(nextPage) || 1), 1, totalPages));
    },
    [totalPages],
  );

  const setRowsPerPage = React.useCallback(
    (nextRowsPerPage: number) => {
      const normalized = normalizeRowsPerPageValue(nextRowsPerPage, rowsPerPageOptions);
      setRowsPerPageState(normalized);
      setPageState(1);
    },
    [rowsPerPageOptions],
  );

  const pagedRows = React.useMemo(() => {
    const start = (page - 1) * rowsPerPage;
    return rows.slice(start, start + rowsPerPage);
  }, [page, rows, rowsPerPage]);

  const pagination = React.useMemo<DashboardTablePaginationConfig>(
    () => ({
      page,
      totalPages,
      totalRows,
      rowsPerPage,
      rowsPerPageOptions,
      quickJumpPages: options.quickJumpPages,
      quickJumpThreshold: options.quickJumpThreshold,
      showJumpToPageInput: options.showJumpToPageInput,
      itemLabel: options.itemLabel,
      itemLabelPlural: options.itemLabelPlural,
      disabled: options.disabled,
      onPageChange: setPage,
      onRowsPerPageChange: setRowsPerPage,
    }),
    [
      options.disabled,
      options.itemLabel,
      options.itemLabelPlural,
      options.quickJumpPages,
      options.quickJumpThreshold,
      options.showJumpToPageInput,
      page,
      rowsPerPage,
      rowsPerPageOptions,
      setPage,
      setRowsPerPage,
      totalPages,
      totalRows,
    ],
  );

  return {
    page,
    rows: pagedRows,
    rowsPerPage,
    setPage,
    setRowsPerPage,
    totalPages,
    totalRows,
    pagination,
  };
}

export function dashboardTableToneClassName(
  baseClassName: string,
  tone: DashboardTableTone = 'neutral',
): string {
  return `${baseClassName} ${baseClassName}--${tone}`;
}

export function DashboardTable(props: DashboardTableProps): React.JSX.Element {
  const { ariaLabel, columns, className, pagination, children } = props;
  return (
    <section
      className={clsx('dashboard-data-table', className)}
      aria-label={ariaLabel}
      role="table"
      style={buildTableStyle(columns)}
    >
      {children}
      {pagination && pagination.totalRows > 0 && !pagination.disabled ? (
        <DashboardTablePagination pagination={pagination} />
      ) : null}
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

export function DashboardTablePagination(props: {
  pagination: DashboardTablePaginationConfig;
}): React.JSX.Element {
  const { pagination } = props;
  const {
    className,
    disabled = false,
    onPageChange,
    onRowsPerPageChange,
    page,
    quickJumpPages,
    quickJumpThreshold,
    rowsPerPage,
    showJumpToPageInput,
    totalPages,
    rowsPerPageOptions,
  } = pagination;
  const jumpTargets = React.useMemo(
    () => buildPaginationJumpTargets(totalPages, quickJumpPages, quickJumpThreshold),
    [quickJumpPages, quickJumpThreshold, totalPages],
  );
  const pageSizeOptions = React.useMemo(
    () => normalizeRowsPerPageOptions(rowsPerPageOptions),
    [rowsPerPageOptions],
  );
  const controlsDisabled = disabled || pagination.totalRows <= 0;
  const showPageJumpInput = showJumpToPageInput !== false && totalPages > 1;
  const [jumpToPageValue, setJumpToPageValue] = React.useState<string>(String(page));

  React.useEffect(() => {
    setJumpToPageValue(String(page));
  }, [page]);

  const commitJumpToPage = React.useCallback(() => {
    if (controlsDisabled) return;
    const nextPage = Math.floor(Number(jumpToPageValue) || 0);
    if (nextPage < 1) {
      setJumpToPageValue(String(page));
      return;
    }
    const normalizedPage = clampNumber(nextPage, 1, totalPages);
    setJumpToPageValue(String(normalizedPage));
    if (normalizedPage !== page) {
      onPageChange(normalizedPage);
    }
  }, [controlsDisabled, jumpToPageValue, onPageChange, page, totalPages]);

  return (
    <div className={clsx('dashboard-data-table__pagination', className)}>
      <span className="dashboard-data-table__pagination-summary">
        {buildPaginationSummary(pagination)}
      </span>
      <div className="dashboard-data-table__pagination-controls">
        <div className="dashboard-data-table__pagination-nav">
          <button
            type="button"
            className="dashboard-pagination-button"
            disabled={controlsDisabled || page <= 1}
            onClick={() => onPageChange(page - 1)}
          >
            Previous
          </button>
          <span
            className="dashboard-data-table__pagination-page"
            aria-label={`Current page ${page} of ${totalPages}`}
          >
            Page {page} | {totalPages}
          </span>
          <button
            type="button"
            className="dashboard-pagination-button"
            disabled={controlsDisabled || page >= totalPages}
            onClick={() => onPageChange(page + 1)}
          >
            Next
          </button>
        </div>
        {jumpTargets.length > 0 ? (
          <div className="dashboard-data-table__pagination-jumps" aria-label="Jump to page">
            <span className="dashboard-pagination-note">Jump to</span>
            {jumpTargets.map((target) => (
              <button
                key={`${target.label}-${target.page}`}
                type="button"
                className="dashboard-data-table__pagination-jump-button"
                disabled={controlsDisabled || target.page === page}
                onClick={() => onPageChange(target.page)}
              >
                {target.label}
              </button>
            ))}
          </div>
        ) : null}
      </div>
      {showPageJumpInput || onRowsPerPageChange ? (
        <div className="dashboard-data-table__pagination-tools">
          {showPageJumpInput ? (
            <form
              className="dashboard-data-table__pagination-jump-form"
              onSubmit={(event) => {
                event.preventDefault();
                commitJumpToPage();
              }}
            >
              <label className="dashboard-data-table__pagination-jump-label">
                <span className="dashboard-pagination-note">Jump to page</span>
                <input
                  className="dashboard-input dashboard-data-table__pagination-jump-input"
                  type="number"
                  min={1}
                  max={totalPages}
                  step={1}
                  inputMode="numeric"
                  value={jumpToPageValue}
                  disabled={controlsDisabled}
                  onChange={(event) => setJumpToPageValue(event.target.value)}
                  onBlur={commitJumpToPage}
                />
              </label>
            </form>
          ) : null}
          {onRowsPerPageChange ? (
            <label className="dashboard-data-table__pagination-size">
              <span className="dashboard-pagination-note">Rows</span>
              <select
                className="dashboard-input dashboard-data-table__pagination-select"
                value={rowsPerPage}
                disabled={disabled}
                onChange={(event) => onRowsPerPageChange(Number(event.target.value))}
              >
                {pageSizeOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </div>
      ) : null}
    </div>
  );
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
