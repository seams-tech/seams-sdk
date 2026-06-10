import type { FC } from 'react';

type SpinnerIconProps = {
  className?: string;
};

export const SpinnerIcon: FC<SpinnerIconProps> = ({ className }) => {
  const classes = ['w3a-menu-spinner-icon', className].filter(Boolean).join(' ');
  return (
    <svg
      className={classes}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="8.5" className="w3a-menu-spinner-icon-track" />
      <path
        d="M20.5 12A8.5 8.5 0 0 0 12 3.5"
        className="w3a-menu-spinner-icon-head"
        strokeLinecap="round"
      />
    </svg>
  );
};

export default SpinnerIcon;
