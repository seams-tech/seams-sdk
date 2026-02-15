import React from 'react'

export function SearchUserWalletsPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Search wallets page">
      <section className="dashboard-filters" aria-label="Wallet search controls">
        <label className="dashboard-search-control">
          <span className="dashboard-search-icon" aria-hidden="true" />
          <input type="search" placeholder="Search by wallet address, wallet ID, user ID, or external reference ID" aria-label="Search wallets" />
        </label>

        <button type="button" className="dashboard-select-control">
          <span className="dashboard-select-control__value">All chains</span>
          <span className="dashboard-chevron" aria-hidden="true" />
        </button>

        <button type="button" className="dashboard-select-control">
          <span className="dashboard-select-control__value">Any policy</span>
          <span className="dashboard-chevron" aria-hidden="true" />
        </button>

        <button type="button" className="dashboard-select-control">
          <span className="dashboard-select-control__value">EOA + Smart</span>
          <span className="dashboard-chevron" aria-hidden="true" />
        </button>

        <button type="button" className="dashboard-columns-control">
          <span className="dashboard-columns-icon" aria-hidden="true" />
          <span>Sort</span>
        </button>
      </section>

      <section className="dashboard-view__section">
        <h2>Search and filter model</h2>
        <ul className="dashboard-view-list">
          <li>Filter by chain, policy, key quorum, wallet type, status, and date range.</li>
          <li>Sort by balance, last activity, and creation time.</li>
          <li>Persist filter state in URL query params for shareable views.</li>
          <li>Return empty/loading/error states with retry actions.</li>
        </ul>
      </section>
    </div>
  )
}

export default SearchUserWalletsPage
