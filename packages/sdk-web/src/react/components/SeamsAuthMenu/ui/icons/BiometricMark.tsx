import React from 'react';

interface FingerprintIconProps {
  size?: number;
  className?: string;
  color?: string;
  strokeWidth?: number;
  style?: React.CSSProperties;
}

export const FingerprintIcon: React.FC<FingerprintIconProps> = ({
  size = 24,
  className = '',
  color = 'currentColor',
  strokeWidth = 1.5,
  style,
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      style={style}
    >
      <path d="M6.405 19.048c.184-.443.353-.894.507-1.351" />
      <path d="M14.343 20.693c.266-.751.502-1.516.707-2.294.186-.706.346-1.422.478-2.147" />
      <path d="M19.448 17.058c.364-1.964.555-3.989.555-6.058 0-4.418-3.582-8-8-8-1.255 0-2.443.289-3.501.805" />
      <path d="M3.523 15.025c.314-1.29.48-2.638.48-4.025 0-1.74.556-3.351 1.499-4.664" />
      <path d="M12.003 11c0 2.76-.447 5.416-1.273 7.899-.213.639-.451 1.266-.712 1.881" />
      <path d="M7.712 14.5c.191-1.138.291-2.308.291-3.5 0-2.209 1.791-4 4-4s4 1.791 4 4c0 .617-.02 1.229-.058 1.836" />
    </svg>
  );
};

export default FingerprintIcon;
