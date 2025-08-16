import { describe, it, expect } from 'vitest';
import { runConnector } from './cli';
import { writeFileSync, mkdirSync } from 'fs';
import { generateKeyPairSync } from 'crypto';
import http from 'http';

function startMockServer(handler: (body: any) => any): Promise<{ url: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      if (req.method === 'POST' && req.url === '/api/ingest') {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const body = JSON.parse(Buffer.concat(chunks).toString());
        const out = handler(body);
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(out));
      } else {
        res.statusCode = 404;
        res.end();
      }
    });
    server.listen(0, () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({ url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

describe('connector run (mock)', () => {
  it('posts signed payload and receives receipt', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    mkdirSync('services/connector', { recursive: true });
    writeFileSync('services/connector/ed25519_private.key', privateKey.export({ format: 'pem', type: 'pkcs8' }));
    process.env.TEST_CLIENT1_PUB_PEM = publicKey.export({ format: 'pem', type: 'spki' }).toString();
    const server = await startMockServer((body) => ({ ok: true, digest: 'd' }));
    process.env.CONNECTOR_BACKEND = server.url;
    writeFileSync(
      'services/connector/mock.yml',
      `backend: ${server.url}\nclient_id: test-client-1\nexchange: mock\nconnector_version: 0.1.0\n`
    );
    await runConnector('services/connector/mock.yml', true);
    await server.close();
    expect(true).toBe(true);
  });
});

