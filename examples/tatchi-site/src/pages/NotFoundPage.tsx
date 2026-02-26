import React from 'react';
import { useSiteRouter } from '../hooks/useSiteRouter';
import { SitePageFrame } from './SitePageFrame';

export function NotFoundPage(): React.JSX.Element {
  const { linkProps } = useSiteRouter();
  const homeProps = linkProps('/');

  return (
    <SitePageFrame
      title="Page Not Found"
      subtitle="The page you requested does not exist in the current site routes."
    >
      <article className="site-card">
        <p>Try returning to the homepage or navigating with the top menu.</p>
        <p>
          <a href={homeProps.href} onClick={homeProps.onClick}>
            Go to Home
          </a>
        </p>
      </article>
    </SitePageFrame>
  );
}

export default NotFoundPage;
