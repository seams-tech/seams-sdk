import React from 'react';

export interface DashboardGoogleAuthCardClassNames {
  root: string;
  header: string;
  heading: string;
  eyebrow: string;
  title?: string;
  copy: string;
  provider: string;
  providerIcon: string;
  providerBody: string;
  providerLabel: string;
  providerCopy: string;
  ctaButton: string;
  ctaIcon: string;
  note: string;
  error: string;
}

export interface DashboardGoogleAuthCardProps {
  classNames: DashboardGoogleAuthCardClassNames;
  titleId: string;
  title: string;
  titleTag?: 'h1' | 'h2';
  rootAttributes?: Omit<React.HTMLAttributes<HTMLDivElement>, 'className'>;
  closeControl?: React.ReactNode;
  description: string;
  providerLabel: string;
  providerDescription: string;
  continueLabel: string;
  continueDisabled: boolean;
  onContinue: () => void;
  note: string;
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

export function DashboardGoogleAuthCard({
  classNames,
  titleId,
  title,
  titleTag = 'h2',
  rootAttributes,
  closeControl,
  description,
  providerLabel,
  providerDescription,
  continueLabel,
  continueDisabled,
  onContinue,
  note,
  errorMessage,
}: DashboardGoogleAuthCardProps): React.JSX.Element {
  const TitleTag = titleTag;
  return (
    <div className={classNames.root} aria-labelledby={titleId} {...rootAttributes}>
      <div className={classNames.header}>
        <div className={classNames.heading}>
          <p className={classNames.eyebrow}>Dashboard</p>
          <TitleTag id={titleId} className={classNames.title}>
            {title}
          </TitleTag>
        </div>
        {closeControl}
      </div>
      <p className={classNames.copy}>{description}</p>
      <div className={classNames.provider}>
        <div className={classNames.providerIcon} aria-hidden="true">
          <GoogleMark />
        </div>
        <div className={classNames.providerBody}>
          <p className={classNames.providerLabel}>{providerLabel}</p>
          <p className={classNames.providerCopy}>{providerDescription}</p>
        </div>
      </div>
      <button
        type="button"
        className={classNames.ctaButton}
        onClick={() => onContinue()}
        disabled={continueDisabled}
      >
        <span className={classNames.ctaIcon} aria-hidden="true">
          <GoogleMark />
        </span>
        <span>{continueLabel}</span>
      </button>
      <p className={classNames.note}>{note}</p>
      {errorMessage ? (
        <p className={classNames.error} role="alert">
          {errorMessage}
        </p>
      ) : null}
    </div>
  );
}

export default DashboardGoogleAuthCard;
