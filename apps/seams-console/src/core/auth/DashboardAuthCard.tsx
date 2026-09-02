import React from 'react';

export interface DashboardAuthCardClassNames {
  root: string;
  header: string;
  heading: string;
  copy: string;
  ctaGroup: string;
  ctaButton: string;
  ctaIcon: string;
  note: string;
  error: string;
}

export type DashboardAuthProvider = {
  id: 'google' | 'github';
  label: string;
  disabled: boolean;
  onContinue: () => void;
};

export interface DashboardAuthCardProps {
  classNames: DashboardAuthCardClassNames;
  titleId: string;
  title: string;
  description: string;
  providers: readonly DashboardAuthProvider[];
  note?: string;
  errorMessage?: string;
}

function GoogleMark(): React.JSX.Element {
  return (
    <svg viewBox="0 0 24 24" focusable="false">
      <path
        fill="#4285F4"
        d="M21.6 12.23c0-.68-.06-1.34-.18-1.98H12v3.74h5.39a4.6 4.6 0 0 1-2 3.02v2.5h3.23c1.9-1.75 2.98-4.34 2.98-7.28Z"
      />
      <path
        fill="#34A853"
        d="M12 22c2.7 0 4.97-.9 6.63-2.44l-3.23-2.5c-.9.6-2.04.96-3.4.96-2.62 0-4.84-1.77-5.63-4.15H3.03v2.57A10 10 0 0 0 12 22Z"
      />
      <path
        fill="#FBBC04"
        d="M6.37 13.87A5.99 5.99 0 0 1 6.05 12c0-.65.11-1.28.32-1.87V7.56H3.03A10 10 0 0 0 2 12c0 1.6.38 3.11 1.03 4.44l3.34-2.57Z"
      />
      <path
        fill="#EA4335"
        d="M12 5.98c1.47 0 2.78.5 3.82 1.48l2.86-2.86C16.96 2.98 14.7 2 12 2a10 10 0 0 0-8.97 5.56l3.34 2.57c.79-2.38 3-4.15 5.63-4.15Z"
      />
    </svg>
  );
}

function GithubMark(): React.JSX.Element {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" focusable="false">
      <path d="M12 2C6.48 2 2 6.58 2 12.23c0 4.52 2.87 8.35 6.84 9.71.5.1.68-.22.68-.49 0-.24-.01-1.05-.01-1.91-2.78.62-3.37-1.2-3.37-1.2-.45-1.18-1.11-1.49-1.11-1.49-.91-.64.07-.62.07-.62 1 .07 1.53 1.06 1.53 1.06.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.06 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.28 2.75 1.05A9.32 9.32 0 0 1 12 6.96c.85 0 1.69.12 2.49.34 1.91-1.33 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.93-2.34 4.79-4.57 5.04.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.8 0 .27.18.59.69.49A10.25 10.25 0 0 0 22 12.23C22 6.58 17.52 2 12 2Z" />
    </svg>
  );
}

function ProviderMark({ provider }: { provider: DashboardAuthProvider['id'] }): React.JSX.Element {
  switch (provider) {
    case 'google':
      return <GoogleMark />;
    case 'github':
      return <GithubMark />;
  }
}

function DashboardAuthProviderButton({
  classNames,
  provider,
}: {
  classNames: DashboardAuthCardClassNames;
  provider: DashboardAuthProvider;
}): React.JSX.Element {
  return (
    <button
      type="button"
      className={classNames.ctaButton}
      onClick={provider.onContinue}
      disabled={provider.disabled}
    >
      <span className={classNames.ctaIcon} aria-hidden="true">
        <ProviderMark provider={provider.id} />
      </span>
      <span>{provider.label}</span>
    </button>
  );
}

export function DashboardAuthCard({
  classNames,
  titleId,
  title,
  description,
  providers,
  note,
  errorMessage,
}: DashboardAuthCardProps): React.JSX.Element {
  const providerButtons: React.JSX.Element[] = [];
  for (const provider of providers) {
    providerButtons.push(
      <DashboardAuthProviderButton key={provider.id} classNames={classNames} provider={provider} />,
    );
  }
  return (
    <div className={classNames.root} aria-labelledby={titleId}>
      <div className={classNames.header}>
        <div className={classNames.heading}>
          <h1 id={titleId}>{title}</h1>
        </div>
      </div>
      <p className={classNames.copy}>{description}</p>
      <div className={classNames.ctaGroup}>{providerButtons}</div>
      {note ? <p className={classNames.note}>{note}</p> : null}
      {errorMessage ? (
        <p className={classNames.error} role="alert">
          {errorMessage}
        </p>
      ) : null}
    </div>
  );
}

export default DashboardAuthCard;
