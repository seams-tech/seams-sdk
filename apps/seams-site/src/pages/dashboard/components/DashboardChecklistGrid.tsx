import React from 'react';
import type { DashboardChecklistCard } from './dashboardContent';

type DashboardChecklistGridProps = {
  cards: readonly DashboardChecklistCard[];
};

export function DashboardChecklistGrid({ cards }: DashboardChecklistGridProps): React.JSX.Element {
  return (
    <section className="dashboard-view-grid dashboard-view-grid--two">
      {cards.map((card) => (
        <article className="dashboard-view-card" key={card.title}>
          <h2>{card.title}</h2>
          <ul className="dashboard-view-list">
            {card.items.map((item) => (
              <li key={`${card.title}:${item}`}>{item}</li>
            ))}
          </ul>
        </article>
      ))}
    </section>
  );
}

export default DashboardChecklistGrid;
