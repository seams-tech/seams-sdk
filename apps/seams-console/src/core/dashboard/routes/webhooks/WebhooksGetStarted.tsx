import React from 'react';
import { CopyButton } from '@core/components/CopyButton';
import { getDocsOrigin } from '@core/router/siteRouting';
import { ArrowRightIcon, PlusIcon, ServerIcon, WebhookIcon } from '../../icons/SidebarIcons';
import { WEBHOOK_EVENT_CATEGORY_OPTIONS } from './webhookEventCatalog';

const VERIFY_SIGNATURE_SNIPPET = `const signed = \`\${timestamp}.\${rawBody}\`;
const mac = createHmac('sha256', secret)
  .update(signed)
  .digest('hex');
// signature header === \`v1=\${mac}\``;

export function WebhooksGetStarted(props: {
  onAddEndpoint: () => void;
  disabled: boolean;
}): React.JSX.Element {
  const { onAddEndpoint, disabled } = props;

  return (
    <section className="dashboard-webhooks-start" aria-label="Get started with webhooks">
      <div className="dashboard-webhooks-start__hero">
        <div className="dashboard-webhooks-start__glyphs" aria-hidden="true">
          <span className="dashboard-webhooks-start__glyph">
            <WebhookIcon size={20} strokeWidth={1.75} />
          </span>
          <ArrowRightIcon
            size={16}
            strokeWidth={1.75}
            className="dashboard-webhooks-start__arrow"
          />
          <span className="dashboard-webhooks-start__glyph">
            <ServerIcon size={20} strokeWidth={1.75} />
          </span>
        </div>
        <h2 className="dashboard-webhooks-start__title">Send Seams events to your backend</h2>
        <p className="dashboard-webhooks-start__lede">
          Seams POSTs a signed callback when something happens in this org. Every attempt is logged
          here, and can be replayed.{' '}
          <a
            className="dashboard-inline-link"
            href={getDocsOrigin()}
            target="_blank"
            rel="noreferrer"
          >
            Learn more
          </a>
        </p>
        <button
          type="button"
          className="dashboard-pagination-button dashboard-pagination-button--primary dashboard-pagination-button--with-icon"
          onClick={onAddEndpoint}
          disabled={disabled}
        >
          <PlusIcon size={16} strokeWidth={2} />
          Add endpoint
        </button>
      </div>

      <ol className="dashboard-webhooks-start__steps">
        <li className="dashboard-webhooks-start__step">
          <span className="dashboard-webhooks-start__step-index" aria-hidden="true">
            1
          </span>
          <div className="dashboard-webhooks-start__step-copy">
            <h3>Point an endpoint at your server</h3>
            <p>
              A URL, plus the categories it should receive. Each delivery is a JSON envelope:{' '}
              <code>id</code>, <code>type</code>, <code>createdAt</code>, <code>data</code>.
            </p>
            <ul className="dashboard-webhooks-start__chips">
              {WEBHOOK_EVENT_CATEGORY_OPTIONS.map((option) => (
                <li key={option.value} title={option.description}>
                  <code>{option.value}.*</code>
                </li>
              ))}
            </ul>
          </div>
        </li>

        <li className="dashboard-webhooks-start__step">
          <span className="dashboard-webhooks-start__step-index" aria-hidden="true">
            2
          </span>
          <div className="dashboard-webhooks-start__step-copy">
            <h3>Verify the signature</h3>
            <p>
              Every POST carries <code>X-Console-Webhook-Timestamp</code> and{' '}
              <code>X-Console-Webhook-Signature</code>, an HMAC-SHA256 keyed with the
              endpoint&rsquo;s <code>whsec_…</code> secret.
            </p>
            <div className="dashboard-webhooks-start__snippet">
              <pre className="dashboard-code-block">
                <code>{VERIFY_SIGNATURE_SNIPPET}</code>
              </pre>
              <CopyButton
                text={VERIFY_SIGNATURE_SNIPPET}
                ariaLabel="Copy signature verification snippet"
              />
            </div>
          </div>
        </li>

        <li className="dashboard-webhooks-start__step">
          <span className="dashboard-webhooks-start__step-index" aria-hidden="true">
            3
          </span>
          <div className="dashboard-webhooks-start__step-copy">
            <h3>Answer 2xx within 10 seconds</h3>
            <p>
              Anything else fails the delivery and parks it in the dead-letter queue. Fix the
              handler, then replay it from the deliveries table.
            </p>
          </div>
        </li>
      </ol>
    </section>
  );
}
