import React from 'react';
import {
  SEARCH_USER_WALLETS_FILTER_CONTROLS,
  SEARCH_USER_WALLETS_MODEL,
  SEARCH_USER_WALLETS_PLACEHOLDER,
} from '../../components/dashboardContent';

export function SearchUserWalletsPage(): React.JSX.Element {
  return (
    <div className="dashboard-view" aria-label="Search wallets page">
      <section className="dashboard-filters" aria-label="Wallet search controls">
        <label className="dashboard-search-control">
          <span className="dashboard-search-icon" aria-hidden="true" />
          <input
            type="search"
            placeholder={SEARCH_USER_WALLETS_PLACEHOLDER}
            aria-label="Search wallets"
          />
        </label>

        {SEARCH_USER_WALLETS_FILTER_CONTROLS.map((control) =>
          control.kind === 'select' ? (
            <button type="button" className="dashboard-select-control" key={control.value}>
              <span className="dashboard-select-control__value">{control.value}</span>
              <span className="dashboard-chevron" aria-hidden="true" />
            </button>
          ) : (
            <button type="button" className="dashboard-columns-control" key={control.value}>
              <span className="dashboard-columns-icon" aria-hidden="true" />
              <span>{control.value}</span>
            </button>
          ),
        )}
      </section>

      <section className="dashboard-view__section">
        <h2>{SEARCH_USER_WALLETS_MODEL.title}</h2>
        <ul className="dashboard-view-list">
          {SEARCH_USER_WALLETS_MODEL.items.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>
    </div>
  );
}

export default SearchUserWalletsPage;
