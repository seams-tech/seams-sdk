import React from 'react';
import SeamsProfileSettingsButton from '../SeamsProfileSettingsButton';

/**
 * Inline wrapper for AccountMenuButton inside the passkey demo area.
 */
export const NavbarProfileOverlay: React.FC = () => {
  return (
    <div className="passkey-demo__profile-button-slot">
      <SeamsProfileSettingsButton className="navbar-profile-button" />
    </div>
  );
};

export default NavbarProfileOverlay;
