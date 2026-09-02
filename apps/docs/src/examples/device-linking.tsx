import { useState } from 'react';
import { QRScanMode, ShowQRCode, useDeviceLinking } from '@seams/wallet/react';
import type { LinkDeviceFlowEvent, QrLinkedDeviceSessionPayloadV5 } from '@seams/wallet';

function logLinkEvent(event: LinkDeviceFlowEvent): void {
  console.log(event.phase, event.status, event.message);
}

// Device 2: `ShowQRCode` runs the whole start/display/expire cycle, including
// picking the target factor and cancelling an abandoned session.
export function NewDeviceLinkCode() {
  const [isOpen, setIsOpen] = useState(false);

  return (
    <>
      <button onClick={() => setIsOpen(true)}>Show link code</button>
      <ShowQRCode
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
        onEvent={logLinkEvent}
        onError={(error) => console.error('Device link failed', error)}
      />
    </>
  );
}

// Device 1: scan the code and approve.
export function ApproveLinkedDevice(props: { qrData: QrLinkedDeviceSessionPayloadV5 }) {
  const { linkDevice } = useDeviceLinking({
    onEvent: logLinkEvent,
    onError: (error) => console.error('Device link failed', error),
  });

  return (
    <button onClick={() => void linkDevice(props.qrData, QRScanMode.CAMERA)}>Approve device</button>
  );
}
