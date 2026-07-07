import React from 'react';
import { CredibilityBands } from './sections/CredibilityBands';
import { FinalCTA } from './sections/FinalCTA';
import { Footer } from '@/components/Footer';
import { HomeHero } from './sections/HomeHero';
import NavbarStatic from '@/components/Navbar/NavbarStatic';
import { ProductCards } from './sections/ProductCards';
import { SecurityProofStrip } from './sections/SecurityProofStrip';

export function HomePage(): React.JSX.Element {
  return (
    <>
      <NavbarStatic />
      <div className="layout-root">
        <div className="card one">
          <div className="constrained-column">
            <HomeHero />
          </div>
        </div>

        <div className="card three">
          <div className="single-column-content marketing-stack">
            <CredibilityBands />
            <section className="marketing-rail" aria-label="Platform capabilities">
              <ProductCards />
              <SecurityProofStrip />
              <FinalCTA />
            </section>
          </div>
        </div>

        <div className="card five">
          <div className="full-bleed">
            <Footer />
          </div>
        </div>
      </div>
    </>
  );
}
