import { createServer } from 'node:http';
import { Readable } from 'node:stream';
import { createDefaultVoiceIdService } from './index.ts';
import { createVoiceIdFetchHandler } from './routes.ts';

const service = createDefaultVoiceIdService();
const handler = createVoiceIdFetchHandler(service);
const port = Number.parseInt(process.env.PORT ?? '8787', 10);

createServer(async (incoming, outgoing) => {
  const requestInit: RequestInit & { duplex?: 'half' } = {
    method: incoming.method ?? 'GET',
    headers: incoming.headers as HeadersInit,
    body:
      incoming.method === 'GET' || incoming.method === 'HEAD'
        ? null
        : (Readable.toWeb(incoming) as BodyInit),
    duplex: 'half',
  };
  const request = new Request(`http://127.0.0.1:${port}${incoming.url ?? '/'}`, requestInit);
  const response = await handler(request);
  outgoing.writeHead(response.status, Object.fromEntries(response.headers.entries()));
  outgoing.end(Buffer.from(await response.arrayBuffer()));
}).listen(port, '127.0.0.1', () => {
  console.log(`VoiceID dev server listening on http://127.0.0.1:${port}`);
});
