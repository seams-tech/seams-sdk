import React from 'react';
import type { IconProps } from './SunIcon';

export const LockIcon: React.FC<IconProps> = ({
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
    className={`lucide lucide-lock-icon lucide-lock${className ? ` ${className}` : ''}`}
    aria-hidden="true"
    focusable="false"
    {...rest}
  >
    <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

export default LockIcon;
