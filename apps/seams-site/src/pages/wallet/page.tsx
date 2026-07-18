import React from 'react';
import { AuthMenuMode } from '@seams/sdk/react';
import NavbarStatic from '@/components/Navbar/NavbarStatic';
import { H2DemoHero, H2Footer, H2Networks, H2Security, H2Start } from '@/components/h2/sections';
import '@/styles/h2.css';

/* Embedded Wallet product page (ICP: teams that need wallets in their app).
   The live passkey demo IS the hero — the product proves itself in the fold. */

export function WalletPage(): React.JSX.Element {
  return (
    <div className="h2-page h2-page--wallet">
      <NavbarStatic appearance="light" />
      <div className="h2-col">
        <H2DemoHero
          authDefaultModeWhenNoDetectedAccount={AuthMenuMode.Register}
          kicker="Seams · Embedded Wallet"
          title={
            <>
              Non&#8209;custodial wallets, opened with a passkey
            </>
          }
          sub={
            <>
              Embed wallets your users can never lose: keys split between their device and your
              infrastructure, recovery through email and linked devices, and every action signed.
              Register right here to see it work.
            </>
          }
        />
        <H2Networks />
        <H2Security />
        <H2Start />
        <H2Footer />
      </div>
    </div>
  );
}

export default WalletPage;
