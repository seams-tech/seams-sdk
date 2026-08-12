<template>
  <footer class="seams-docs-footer" aria-label="Seams footer">
    <div class="seams-docs-footer__inner">
      <div class="seams-docs-footer__brand">
        <a class="seams-docs-footer__brand-link" href="https://seams.sh" rel="noreferrer">
          <span class="seams-docs-footer__mark" aria-hidden="true">
            <img
              class="seams-docs-footer__mark-image"
              src="/seams-v9/svg/seams-mark-black.svg"
              alt=""
            />
          </span>
          <span>Seams</span>
        </a>
        <p>Key and credential infrastructure for policy-bound digital authority.</p>
      </div>

      <nav class="seams-docs-footer__links" aria-label="Footer navigation">
        <div class="seams-docs-footer__group">
          <h2>Build</h2>
          <a href="/">Start here</a>
          <a href="/getting-started/create-wallet">Create a wallet</a>
          <a href="/getting-started/sign-with-policy">Sign with policy</a>
        </div>
        <div class="seams-docs-footer__group">
          <h2>Learn</h2>
          <a href="/concepts/architecture">Architecture</a>
          <a href="/concepts/auth-methods/">Authentication</a>
          <a href="/concepts/policy/">Policies</a>
        </div>
        <div class="seams-docs-footer__group">
          <h2>Seams</h2>
          <a href="https://seams.sh/dashboard" rel="noreferrer">Dashboard</a>
          <a href="https://seams.sh/pricing/" rel="noreferrer">Pricing</a>
          <a href="https://seams.sh/contact/" rel="noreferrer">Support</a>
          <a href="https://github.com/web3-authn/seams" rel="noreferrer">GitHub</a>
        </div>
      </nav>
    </div>
    <div class="seams-docs-footer__bottom">
      <span>© {{ new Date().getFullYear() }} Seams, Inc.</span>
      <span>Built for applications that need authority with boundaries.</span>
    </div>
  </footer>
</template>
