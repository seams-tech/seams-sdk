import React from 'react'
import TatchiProfileSettingsButton from '../TatchiProfileSettingsButton'

/**
 * Inline wrapper for AccountMenuButton inside the passkey demo area.
 */
export const NavbarProfileOverlay: React.FC = () => {
  return (
    <div className="passkey-demo__profile-button-slot">
      <TatchiProfileSettingsButton className="navbar-profile-button" />
    </div>
  )
}

export default NavbarProfileOverlay
