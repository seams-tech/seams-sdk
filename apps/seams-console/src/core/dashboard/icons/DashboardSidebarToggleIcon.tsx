import React from 'react';

type DashboardSidebarToggleIconProps = {
  size?: number;
  strokeWidth?: number;
  className?: string;
};

export function DashboardSidebarToggleIcon({
  size = 18,
  strokeWidth = 2,
  className,
}: DashboardSidebarToggleIconProps): React.JSX.Element {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={`dashboard-sidebar-toggle__icon${className ? ` ${className}` : ''}`}
      aria-hidden="true"
      focusable="false"
    >
      <path d="M4 7h16" />
      <path d="M4 12h16" />
      <path d="M4 17h16" />
    </svg>
  );
}

export default DashboardSidebarToggleIcon;
