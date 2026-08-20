import React from 'react';

type DashboardSidebarToggleIconProps = {
  size?: number;
  className?: string;
  /** Collapsed shows a filled panel (what the click restores); expanded shows
      the rail already in place as a hairline divider. */
  expanded?: boolean;
};

export function DashboardSidebarToggleIcon({
  size = 20,
  className,
  expanded = true,
}: DashboardSidebarToggleIconProps): React.JSX.Element {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      className={`dashboard-sidebar-toggle__icon${className ? ` ${className}` : ''}`}
      aria-hidden="true"
      focusable="false"
    >
      {expanded ? (
        <rect
          x="7"
          y="6.5"
          width="7"
          height="1.5"
          rx="0.75"
          transform="rotate(90 7 6.5)"
          fill="currentColor"
        />
      ) : (
        <rect
          x="10.5"
          y="6.5"
          width="7"
          height="5"
          rx="1"
          transform="rotate(90 10.5 6.5)"
          fill="currentColor"
        />
      )}
      <rect x="3" y="4" width="14" height="12" rx="2.8" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

export default DashboardSidebarToggleIcon;
