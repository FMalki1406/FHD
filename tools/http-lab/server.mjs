import http from 'node:http';
import { createHash } from 'node:crypto';

// Intentionally small, deterministic fixtures. No user files or URLs are served.
export function makeFixture(version = 1) {
  const body = Buffer.alloc(65_536);
  for (let offset = 0; offset < body.length; offset += 32) {
    createHash('sha256').update(`fhd-fixture:${version}:${offset / 32}`).digest().copy(body, offset);
  }
  return body;
}

function parseRange(value, length) {
  const match = /^bytes=(\d*)-(\d*)$/.exec(value);
  if (!match || (!match[1] && !match[2])) return null;
  const left = match[1] ? Number(match[1]) : null;
  const right = match[2] ? Number(match[2]) : null;
  if ((left !== null && !Number.isSafeInteger(left)) ||
      (right !== null && !Number.isSafeInteger(right))) return null;
  const start = left ?? Math.max(0, length - right);
  const end = left === null ? length - 1 : Math.min(right ?? length - 1, length - 1);
  if (start >= length || start > end) return null;
  return { start, end };
}

export async function startLab({ port = 0 } = {}) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new RangeError('Invalid port');
  let revision = 1;
  let data = makeFixture(revision);
  let etag = `"${createHash('sha256').update(data).digest('hex')}"`;
  // Stateful scenarios are isolated from /file and from each other.
  const onceStates = new Map(['/drop-once', '/changed-once', '/wrong-range-once', '/no-range-once'].map(path => [path, {
    dropped: false,
    data: makeFixture(1),
    etag: `"${createHash('sha256').update(makeFixture(1)).digest('hex')}"`,
  }]));
  const timers = new Set();
  const sockets = new Set();
  const routes = new Set(['/file', '/no-range', '/drop', '/short-body', '/wrong-range', '/slow', ...onceStates.keys()]);

  const server = http.createServer((req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    // Fixture-only guard: reject unexpected Host, Origin, and proxy-style targets.
    // This is not authentication and does not exclude every browser-originated request.
    const host = `127.0.0.1:${server.address().port}`;
    if (req.headers.host !== host || req.headers.origin || !req.url.startsWith('/')) {
      res.writeHead(403).end();
      return;
    }
    if (!['GET', 'HEAD'].includes(req.method)) {
      res.writeHead(405, { Allow: 'GET, HEAD' }).end();
      return;
    }
    let url;
    try {
      if (req.url.startsWith('//')) throw new Error('Network-path request target');
      url = new URL(req.url, `http://${host}`);
      if (url.origin !== `http://${host}`) throw new Error('Unexpected origin');
    } catch {
      res.writeHead(400).end();
      return;
    }
    if (url.pathname === '/redirect' || url.pathname === '/loop') {
      res.writeHead(302, { Location: url.pathname === '/loop' ? '/loop' : '/file' }).end();
      return;
    }
    if (url.pathname.startsWith('/status/')) {
      const status = Number(url.pathname.slice('/status/'.length));
      if (![403, 404, 429, 500, 502, 503].includes(status)) {
        res.writeHead(400).end();
        return;
      }
      res.writeHead(status, status === 429 || status === 503 ? { 'Retry-After': '1' } : {}).end();
      return;
    }
    if (!routes.has(url.pathname)) {
      res.writeHead(404).end();
      return;
    }

    // Snapshot the revision so concurrent mutations never change an in-flight response.
    const onceState = onceStates.get(url.pathname);
    const body = onceState?.data ?? data;
    const validator = onceState?.etag ?? etag;
    const supportRange = !['/no-range', '/no-range-once'].includes(url.pathname);
    res.setHeader('ETag', validator);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="fixture.bin"');
    res.setHeader('Accept-Ranges', supportRange ? 'bytes' : 'none');

    let selected = { start: 0, end: body.length - 1 };
    let status = 200;
    // If-Range mismatch deliberately returns the entire representation, never old bytes.
    if (req.method === 'GET' && supportRange && req.headers.range &&
        (!req.headers['if-range'] || req.headers['if-range'] === validator)) {
      selected = parseRange(req.headers.range, body.length);
      if (!selected) {
        res.writeHead(416, { 'Content-Range': `bytes */${body.length}` }).end();
        return;
      }
      status = 206;
      const reportedStart = selected.start + (['/wrong-range', '/wrong-range-once'].includes(url.pathname) ? 1 : 0);
      res.setHeader('Content-Range', `bytes ${reportedStart}-${selected.end}/${body.length}`);
    }
    const payload = body.subarray(selected.start, selected.end + 1);
    res.writeHead(status, { 'Content-Length': payload.length });
    if (req.method === 'HEAD') {
      res.end();
      return;
    }
    const dropOnce = onceState && !onceState.dropped && !req.headers.range;
    if (dropOnce) {
      onceState.dropped = true;
      if (url.pathname === '/changed-once') {
        onceState.data = makeFixture(2);
        onceState.etag = `"${createHash('sha256').update(onceState.data).digest('hex')}"`;
      }
    }
    if (dropOnce || url.pathname === '/drop' || url.pathname === '/short-body') {
      res.flushHeaders();
      res.write(payload.subarray(0, Math.floor(payload.length / 2)), () => {
        if (dropOnce || url.pathname === '/drop') res.destroy();
        else res.end();
      });
      return;
    }
    if (url.pathname === '/slow') {
      let offset = 0;
      let timer;
      const schedule = () => {
        if (res.destroyed) return;
        timer = setTimeout(send, 5);
        timers.add(timer);
      };
      const send = () => {
        timers.delete(timer);
        if (res.destroyed) return;
        const next = Math.min(offset + 4096, payload.length);
        const writable = res.write(payload.subarray(offset, next));
        offset = next;
        if (offset === payload.length) res.end();
        else if (writable) schedule();
        else res.once('drain', schedule);
      };
      res.on('close', () => { clearTimeout(timer); timers.delete(timer); });
      schedule();
      return;
    }
    res.end(payload);
  });
  server.requestTimeout = 5_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 100;
  server.maxConnections = 64;
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    changeVersion() {
      revision += 1;
      data = makeFixture(revision);
      etag = `"${createHash('sha256').update(data).digest('hex')}"`;
      return etag;
    },
    async close() {
      for (const timer of timers) clearTimeout(timer);
      timers.clear();
      const closed = new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      for (const socket of sockets) socket.destroy();
      await closed;
    },
  };
}
