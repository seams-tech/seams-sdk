import React from 'react';
import type { SidebarIconProps } from '../types';

// Source: https://lucide.dev/api/icons/{icon-name}
type SidebarIconBaseProps = SidebarIconProps & {
  iconName: string;
  children: React.ReactNode;
};

function SidebarIconBase({
  iconName,
  children,
  size = 20,
  strokeWidth = 2,
  className,
  ...rest
}: SidebarIconBaseProps): React.JSX.Element {
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
      className={`lucide lucide-${iconName}${className ? ` ${className}` : ''}`}
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const LayoutDashboardIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="layout-dashboard" {...props}>
    <rect width="7" height="9" x="3" y="3" rx="1" />
    <rect width="7" height="5" x="14" y="3" rx="1" />
    <rect width="7" height="9" x="14" y="12" rx="1" />
    <rect width="7" height="5" x="3" y="16" rx="1" />
  </SidebarIconBase>
);

export const ActivityIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="activity" {...props}>
    <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2" />
  </SidebarIconBase>
);

export const UserCogIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="user-cog" {...props}>
    <path d="M10 15H6a4 4 0 0 0-4 4v2" />
    <path d="m14.305 16.53.923-.382" />
    <path d="m15.228 13.852-.923-.383" />
    <path d="m16.852 12.228-.383-.923" />
    <path d="m16.852 17.772-.383.924" />
    <path d="m19.148 12.228.383-.923" />
    <path d="m19.53 18.696-.382-.924" />
    <path d="m20.772 13.852.924-.383" />
    <path d="m20.772 16.148.924.383" />
    <circle cx="18" cy="15" r="3" />
    <circle cx="9" cy="7" r="4" />
  </SidebarIconBase>
);

export const CogIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="cog" {...props}>
    <path d="M11 10.27 7 3.34" />
    <path d="m11 13.73-4 6.93" />
    <path d="M12 22v-2" />
    <path d="M12 2v2" />
    <path d="M14 12h8" />
    <path d="m17 20.66-1-1.73" />
    <path d="m17 3.34-1 1.73" />
    <path d="M2 12h2" />
    <path d="m20.66 17-1.73-1" />
    <path d="m20.66 7-1.73 1" />
    <path d="m3.34 17 1.73-1" />
    <path d="m3.34 7 1.73 1" />
    <circle cx="12" cy="12" r="2" />
    <circle cx="12" cy="12" r="8" />
  </SidebarIconBase>
);

export const KeyRoundIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="key-round" {...props}>
    <path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z" />
    <circle cx="16.5" cy="7.5" r=".5" fill="currentColor" />
  </SidebarIconBase>
);

export const WalletCardsIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="wallet-cards" {...props}>
    <rect width="18" height="18" x="3" y="3" rx="2" />
    <path d="M3 9a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2" />
    <path d="M3 11h3c.8 0 1.6.3 2.1.9l1.1.9c1.6 1.6 4.1 1.6 5.7 0l1.1-.9c.5-.5 1.3-.9 2.1-.9H21" />
  </SidebarIconBase>
);

export const FuelIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="fuel" {...props}>
    <path d="M14 13h2a2 2 0 0 1 2 2v2a2 2 0 0 0 4 0v-6.998a2 2 0 0 0-.59-1.42L18 5" />
    <path d="M14 21V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v16" />
    <path d="M2 21h13" />
    <path d="M3 9h11" />
  </SidebarIconBase>
);

export const ScaleIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="scale" {...props}>
    <path d="M12 3v18" />
    <path d="m19 8 3 8a5 5 0 0 1-6 0zV7" />
    <path d="M3 7h1a17 17 0 0 0 8-2 17 17 0 0 0 8 2h1" />
    <path d="m5 8 3 8a5 5 0 0 1-6 0zV7" />
    <path d="M7 21h10" />
  </SidebarIconBase>
);

export const ScrollTextIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="scroll-text" {...props}>
    <path d="M15 12h-5" />
    <path d="M15 8h-5" />
    <path d="M19 17V5a2 2 0 0 0-2-2H4" />
    <path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3" />
  </SidebarIconBase>
);

export const ServerCogIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="server-cog" {...props}>
    <path d="m10.852 14.772-.383.923" />
    <path d="M13.148 14.772a3 3 0 1 0-2.296-5.544l-.383-.923" />
    <path d="m13.148 9.228.383-.923" />
    <path d="m13.53 15.696-.382-.924a3 3 0 1 1-2.296-5.544" />
    <path d="m14.772 10.852.923-.383" />
    <path d="m14.772 13.148.923.383" />
    <path d="M4.5 10H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-.5" />
    <path d="M4.5 14H4a2 2 0 0 0-2 2v4a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-4a2 2 0 0 0-2-2h-.5" />
    <path d="M6 18h.01" />
    <path d="M6 6h.01" />
    <path d="m9.228 10.852-.923-.383" />
    <path d="m9.228 13.148-.923.383" />
  </SidebarIconBase>
);

export const WebhookIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="webhook" {...props}>
    <path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2" />
    <path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06" />
    <path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8" />
  </SidebarIconBase>
);

export const CreditCardIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="credit-card" {...props}>
    <rect width="20" height="14" x="2" y="5" rx="2" />
    <line x1="2" x2="22" y1="10" y2="10" />
  </SidebarIconBase>
);

export const FileTextIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="file-text" {...props}>
    <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
    <path d="M14 2v4a2 2 0 0 0 2 2h4" />
    <path d="M10 9H8" />
    <path d="M16 13H8" />
    <path d="M16 17H8" />
  </SidebarIconBase>
);

export const ChevronDownIcon: React.FC<SidebarIconProps> = (props) => (
  <SidebarIconBase iconName="chevron-down" {...props}>
    <path d="m6 9 6 6 6-6" />
  </SidebarIconBase>
);
