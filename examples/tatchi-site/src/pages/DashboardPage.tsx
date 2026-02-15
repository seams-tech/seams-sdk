import React from 'react'
import { Footer } from '../components/Footer'
import NavbarStatic from '../components/Navbar/NavbarStatic'
import { DemoPage } from '../components/DemoPage'

export function DashboardPage(): React.JSX.Element {
  return (
    <>
      <NavbarStatic />
      <main className="site-page site-page--dashboard">
        <section className="site-page__hero">
          <p className="site-page__kicker">Dashboard</p>
          <h1 id="site-page-title">Dashboard Mock</h1>
          <p className="site-page__subtitle">
            Interactive signing controls and session-state examples used to validate end-to-end flows.
          </p>
        </section>
        <section className="site-page__content">
          <DemoPage />
        </section>
      </main>
      <Footer />
    </>
  )
}

export default DashboardPage

