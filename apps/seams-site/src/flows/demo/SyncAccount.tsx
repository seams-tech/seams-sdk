import React from 'react';
import { useSeams, PROFILE_MENU_ITEM_IDS } from '@seams/sdk/react';
import { toast } from 'sonner';
import { LoadingButton } from '@/components/LoadingButton';
import { GlassBorder } from '@/components/GlassBorder';
import { useProfileMenuControl } from '@/context/ProfileMenuControl';
import './SyncAccount.css';
import { SetupEmailRecovery } from './SetupEmailRecovery';

export function SyncAccount() {
  const { loginState } = useSeams();
  const { requestHighlight: requestProfileHighlight } = useProfileMenuControl();

  const onLinkDevice = React.useCallback(() => {
    if (!loginState.isLoggedIn) {
      toast.error('Log in to link another device');
      return;
    }
    requestProfileHighlight({
      id: PROFILE_MENU_ITEM_IDS.SCAN_LINK_DEVICE,
      focus: true,
    });
  }, [loginState.isLoggedIn, requestProfileHighlight]);

  /* width matches the auth card and transaction shell (420px): unequal page
     widths make the carousel stage resize on page unmount, which shoves the
     incoming card sideways after the cross-fade */
  return (
    <GlassBorder style={{ width: 'min(420px, calc(100vw - 2rem))', marginTop: '1rem' }}>
      {/* header sits outside the padded section so the title shares the
          content's left edge (same structure as the Welcome menu) */}
      <div className="demo-page-header">
        <h2 className="demo-title">Devices &amp; Recovery</h2>
      </div>
      <div className="action-section">
        {/* the keeper leads with the screen's single primary action */}
        <div className="recovery-section">
          <h3 className="demo-subtitle">Device Linking</h3>
          <div className="action-text">Scan a QR code to link a new device to your account.</div>
          <LoadingButton
            onClick={onLinkDevice}
            variant="primary"
            size="medium"
            style={{ width: 200 }}
          >
            Link Device
          </LoadingButton>
        </div>

        <SetupEmailRecovery />
      </div>
    </GlassBorder>
  );
}

export default SyncAccount;
