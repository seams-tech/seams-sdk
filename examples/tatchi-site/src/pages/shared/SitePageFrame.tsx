import React from 'react';
import { Footer } from '@/components/Footer';
import NavbarStatic from '@/components/Navbar/NavbarStatic';
import './styles.css';

type SitePageFrameProps = {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
};

export function SitePageFrame(props: SitePageFrameProps): React.JSX.Element {
  return (
    <>
      <NavbarStatic />
      <main className="site-page" aria-labelledby="site-page-title">
        <section className="site-page__hero">
          <p className="site-page__kicker">Tatchi</p>
          <h1 id="site-page-title">{props.title}</h1>
          {props.subtitle ? <p className="site-page__subtitle">{props.subtitle}</p> : null}
        </section>
        <section className="site-page__content">{props.children}</section>
      </main>
      <Footer />
    </>
  );
}

export default SitePageFrame;
