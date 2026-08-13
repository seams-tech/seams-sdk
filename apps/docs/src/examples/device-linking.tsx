import { useEffect, useState } from 'react';
import { QRScanMode, useDeviceLinking, useSeams } from '@seams/sdk/react';
import type { LinkDeviceFlowEvent, QrLinkedDeviceSessionPayloadV4 } from '@seams/sdk';

function logLinkEvent(event: LinkDeviceFlowEvent): void {
  console.log(event.phase, event.status, event.message);
}

export function NewDeviceLinkCode() {
  const { startDevice2LinkingFlow, cancelDeviceLinking } = useSeams();
  const [qrCodeDataURL, setQrCodeDataURL] = useState<string | null>(null);

  const onStart = async (): Promise<void> => {
    const link = await startDevice2LinkingFlow({ ui: 'inline' });
    setQrCodeDataURL(link.qrCodeDataURL);
  };

  useEffect(() => {
    return () => {
      void cancelDeviceLinking();
    };
  }, [cancelDeviceLinking]);

  return (
    <>
      <button onClick={() => void onStart()}>Show link code</button>
      {qrCodeDataURL ? <img src={qrCodeDataURL} alt="Device link QR code" /> : null}
    </>
  );
}

export function ApproveLinkedDevice(props: { qrData: QrLinkedDeviceSessionPayloadV4 }) {
  const { linkDevice } = useDeviceLinking({
    onEvent: logLinkEvent,
    onError: (error) => console.error('Device link failed', error),
  });

  return (
    <button onClick={() => void linkDevice(props.qrData, QRScanMode.CAMERA)}>Approve device</button>
  );
}
