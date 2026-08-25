import React from 'react';
import { CopyButton } from '@core/components/CopyButton';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';

const REVEAL_SECRET_TITLE_ID = 'dashboard-webhook-secret-title';

export interface WebhookSecretReveal {
  endpointId: string;
  endpointUrl: string;
  signingSecret: string;
  secretVersion: number;
  reason: 'created' | 'rotated';
}

interface WebhookSecretRevealModalProps {
  reveal: WebhookSecretReveal | null;
  onRequestClose: () => void;
}

/* The plaintext is sealed the moment it is stored, so no read route can hand
   it back. This dialog is the customer's only chance to capture it, which is
   why closing is an explicit acknowledgement rather than an incidental
   dismissal elsewhere in the page. */
function WebhookSecretRevealBody(props: {
  reveal: WebhookSecretReveal;
  onRequestClose: () => void;
}): React.JSX.Element {
  const { reveal, onRequestClose } = props;
  const created = reveal.reason === 'created';

  return (
    <>
      <div className="dashboard-modal__header">
        <h2 id={REVEAL_SECRET_TITLE_ID}>{created ? 'Endpoint added' : 'Signing secret rotated'}</h2>
      </div>

      <p className="dashboard-modal__lede">
        Copy the signing secret for <code>{reveal.endpointUrl}</code> now. Seams stores it encrypted
        and cannot show it again — if you lose it, rotate to mint a replacement.
      </p>

      <div className="dashboard-webhook-secret">
        <span className="dashboard-webhook-secret__label">
          Signing secret <span aria-hidden="true">·</span> v{reveal.secretVersion}
        </span>
        <div className="dashboard-webhook-secret__value">
          <code>{reveal.signingSecret}</code>
          <CopyButton text={reveal.signingSecret} ariaLabel="Copy webhook signing secret" />
        </div>
      </div>

      {!created ? (
        <p className="dashboard-form-alert" role="alert">
          Deliveries are signed with the new secret from now on. Update your handler before the next
          event, or its signature check will fail.
        </p>
      ) : null}

      <div className="dashboard-form-actions">
        <button
          type="button"
          className="dashboard-pagination-button dashboard-pagination-button--primary"
          onClick={onRequestClose}
        >
          I&rsquo;ve saved it
        </button>
      </div>
    </>
  );
}

export function WebhookSecretRevealModal(props: WebhookSecretRevealModalProps): React.JSX.Element {
  const { reveal, onRequestClose } = props;
  return (
    <DashboardInlineModal
      isOpen={Boolean(reveal)}
      ariaLabel="Webhook signing secret"
      ariaLabelledBy={REVEAL_SECRET_TITLE_ID}
      onRequestClose={onRequestClose}
    >
      {reveal ? <WebhookSecretRevealBody reveal={reveal} onRequestClose={onRequestClose} /> : null}
    </DashboardInlineModal>
  );
}

export default WebhookSecretRevealModal;
