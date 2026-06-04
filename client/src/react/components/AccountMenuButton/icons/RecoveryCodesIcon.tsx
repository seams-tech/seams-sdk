import React from 'react';
import type { IconProps } from './SunIcon';

export const RecoveryCodesIcon: React.FC<IconProps> = ({
  size = 24,
  className,
  strokeWidth = 2,
  ...rest
}) => (
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
    className={`lucide lucide-list-key${className ? ` ${className}` : ''}`}
    aria-hidden="true"
    focusable="false"
    {...rest}
  >
    <path d="M9 6h12" />
    <path d="M9 12h12" />
    <path d="M9 18h12" />
    <path d="M4 6h.01" />
    <path d="M4 12h.01" />
    <circle cx="4" cy="18" r="2" />
    <path d="m6 16-1.2 1.2" />
  </svg>
);

export default RecoveryCodesIcon;
