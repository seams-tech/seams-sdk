import React from 'react';
import { toast } from 'sonner';
import {
  useSeams,
  KeyExportEventPhase,
  LinkDeviceEventPhase,
  useTheme,
  type KeyExportFlowEvent,
  type LinkDeviceFlowEvent,
} from '@seams/wallet/react';
import { AccountMenuButton } from '@seams/wallet/react/profile';
import { useProfileMenuControl } from '@/context/ProfileMenuControl';
import {
  dismissDemoEmailOtpToast,
  showCopiedDemoEmailOtpToast,
} from '@/flows/demo/demoEmailOtpToast';

const KEY_EXPORT_EMAIL_OTP_TOAST_ID = 'key-export:demo-email-otp';

function demoEmailOtpCodeFromKeyExportEvent(event: KeyExportFlowEvent): string | null {
  if (event.phase !== KeyExportEventPhase.STEP_02_AUTH_EMAIL_OTP_INPUT_REQUIRED) return null;
  const otpCode = event.data?.demoOtpCode;
  return typeof otpCode === 'string' && /^\d{6}$/.test(otpCode) ? otpCode : null;
}

/* Exported for unit coverage of the toast lifecycle: the demo code must appear
   exactly once per challenge and be dismissed on resend-without-code and on
   every terminal phase. */
export function handleKeyExportEvent(event: KeyExportFlowEvent): void {
  const otpCode = demoEmailOtpCodeFromKeyExportEvent(event);
  if (otpCode) {
    void showCopiedDemoEmailOtpToast({
      otpCode,
      toastId: KEY_EXPORT_EMAIL_OTP_TOAST_ID,
      unavailableDescription: 'Use this one-time code to authorize key export.',
    });
    return;
  }
  if (event.phase === KeyExportEventPhase.STEP_02_AUTH_EMAIL_OTP_INPUT_REQUIRED) {
    dismissDemoEmailOtpToast(KEY_EXPORT_EMAIL_OTP_TOAST_ID);
    return;
  }
  if (
    event.phase === KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED ||
    event.phase === KeyExportEventPhase.STEP_06_COMPLETED ||
    event.phase === KeyExportEventPhase.FAILED ||
    event.phase === KeyExportEventPhase.CANCELLED
  ) {
    dismissDemoEmailOtpToast(KEY_EXPORT_EMAIL_OTP_TOAST_ID);
  }
}

export interface SeamsProfileSettingsButtonProps {
  className?: string;
  style?: React.CSSProperties;
}

export const SeamsProfileSettingsButton: React.FC<SeamsProfileSettingsButtonProps> = ({
  className,
  style,
}) => {
  const { loginState, seams } = useSeams();
  const { theme, setTheme } = useTheme();
  const [isMobile, setIsMobile] = React.useState<boolean>(false);
  const { isMenuOpen, highlightedMenuItem, setMenuOpen, clearHighlight } = useProfileMenuControl();

  // Only handle Device1 events here
  const handleDeviceLinkingEvents = (event: LinkDeviceFlowEvent) => {
    if (event.flow !== 'link_device') return;
    if (event.phase === LinkDeviceEventPhase.CANCELLED || event.status === 'cancelled') {
      toast.info(event.message || 'Device link cancelled', { id: 'device-linking' });
      return;
    }
    if (event.phase === LinkDeviceEventPhase.FAILED || event.status === 'failed') {
      toast.dismiss('device-linking');
      toast.error(event.error?.message || event.message || 'Device linking failed', {
        id: 'device-linking',
      });
      return;
    }
    if (event.status === 'succeeded') {
      toast.success(event.message || 'QR code scanned', {
        id: 'device-linking',
        description: 'Continue setup on your other device.',
      });
      return;
    }
    toast.loading(event.message || 'Processing device link...', { id: 'device-linking' });
  };

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(max-width: 768px)');
    const onChange = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    setIsMobile(mq.matches);
    if ('addEventListener' in mq) mq.addEventListener('change', onChange);
    return () => {
      if ('removeEventListener' in mq) mq.removeEventListener('change', onChange);
    };
  }, []);

  // Expose login state to VitePress DOM for conditional styling + event bridge
  React.useEffect(() => {
    if (typeof document === 'undefined') return;
    try {
      const loggedIn = !!loginState.isLoggedIn;
      const nearId = loginState.nearAccountId || '';
      document.body.setAttribute('data-w3a-logged-in', loggedIn ? 'true' : 'false');
      if (loggedIn && nearId) document.body.setAttribute('data-w3a-near-account-id', nearId);
      else document.body.removeAttribute('data-w3a-near-account-id');
      try {
        window.dispatchEvent(
          new CustomEvent('w3a:login-state', { detail: { loggedIn, nearAccountId: nearId } }),
        );
      } catch {}
    } catch {}
  }, [loginState.isLoggedIn, loginState.nearAccountId]);

  React.useEffect(() => {
    if (!loginState.isLoggedIn) {
      clearHighlight();
      setMenuOpen(false);
    }
  }, [loginState.isLoggedIn, clearHighlight, setMenuOpen]);

  if (!loginState.isLoggedIn) {
    return null;
  } else {
    return (
      <div className="seams-profile-button-container" style={style}>
        <AccountMenuButton
          nearAccountId={loginState.nearAccountId}
          nearExplorerBaseUrl="https://testnet.nearblocks.io"
          onExportKeyError={(error: Error) => {
            console.error('Key export error:', error);
            toast.error(error.message || 'Key export failed', { id: 'key-export' });
          }}
          onExportKeyEvent={handleKeyExportEvent}
          hideUsername={isMobile}
          className={className}
          style={
            {
              // border: 'none',
              // background: 'none',
            }
          }
          deviceLinkingScannerParams={{
            fundingAmount: '0.05',
            onError: (error: Error) => {
              console.error('Device linking error:', error);
              toast.dismiss('device-linking');
              toast.error(`Device linking failed: ${error.message}`, { id: 'device-linking' });
            },
            onClose: () => {
              toast.dismiss();
            },
            onEvent: (event) => handleDeviceLinkingEvents(event),
          }}
          isMenuOpen={isMenuOpen}
          onMenuOpenChange={setMenuOpen}
          highlightedMenuItem={highlightedMenuItem}
        />
      </div>
    );
  }
};

export default SeamsProfileSettingsButton;
