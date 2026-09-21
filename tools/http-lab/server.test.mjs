import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { startLab } from './server.mjs';

function request(url, options = {}) {
  const { onResponse, ...requestOptions } = options;
  return new Promise((resolve, reject) => {
    const req = http.request(url, { agent: false, ...requestOptions }, res => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      onResponse?.(res);
    });
    req.setTimeout(2000, () => req.destroy(new Error('Request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function setup(t) {
  const lab = await startLab();
  t.after(() => lab.close());
  return lab;
}

test('complete file has a verifiable validator and HEAD returns no body', async t => {
  const lab = await setup(t);
  const full = await request(`${lab.url}/file`);
  assert.equal(full.status, 200);
  assert.equal(full.body.length, 65536);
  assert.equal(full.headers.etag, `"${createHash('sha256').update(full.body).digest('hex')}"`);
  const head = await request(`${lab.url}/file`, { method: 'HEAD', headers: { Range: 'bytes=0-3' } });
  assert.equal(head.status, 200);
  assert.equal(head.body.length, 0);
  assert.equal(head.headers['content-length'], '65536');
});

test('parallel ranges reconstruct exactly the full response', async t => {
  const lab = await setup(t);
  const full = await request(`${lab.url}/file`);
  const segments = await Promise.all(Array.from({ length: 8 }, (_, i) =>
    request(`${lab.url}/file`, { headers: { Range: `bytes=${i * 8192}-${(i + 1) * 8192 - 1}`, 'If-Range': full.headers.etag } })));
  for (const [i, result] of segments.entries()) {
    assert.equal(result.status, 206);
    assert.equal(result.headers['content-range'], `bytes ${i * 8192}-${(i + 1) * 8192 - 1}/65536`);
  }
  assert.deepEqual(Buffer.concat(segments.map(s => s.body)), full.body);
  assert.notDeepEqual(segments[0].body, segments[1].body);
  const swapped = [segments[1], segments[0], ...segments.slice(2)];
  assert.notDeepEqual(Buffer.concat(swapped.map(s => s.body)), full.body);
  const repeated = [segments[0], segments[0], ...segments.slice(2)];
  assert.notDeepEqual(Buffer.concat(repeated.map(s => s.body)), full.body);
});

test('open-ended and suffix ranges return the correct bytes', async t => {
  const lab = await setup(t);
  const full = await request(`${lab.url}/file`);
  for (const value of ['bytes=65526-', 'bytes=-10', 'bytes=65526-999999']) {
    const part = await request(`${lab.url}/file`, { headers: { Range: value } });
    assert.equal(part.status, 206);
    assert.deepEqual(part.body, full.body.subarray(-10));
  }
});

test('invalid or unsatisfiable ranges cannot be mistaken for a partial success', async t => {
  const lab = await setup(t);
  for (const value of ['bytes=65536-', 'bytes=10-2', 'bytes=-0', 'bytes=-', 'bytes=0-1,3-4', 'bytes=9007199254740992-']) {
    const result = await request(`${lab.url}/file`, { headers: { Range: value } });
    assert.equal(result.status, 416, value);
    assert.equal(result.headers['content-range'], 'bytes */65536');
  }
});

test('changed same-size file invalidates old If-Range and returns a full new version', async t => {
  const lab = await setup(t);
  const original = await request(`${lab.url}/file`);
  lab.changeVersion();
  const resumed = await request(`${lab.url}/file`, { headers: { Range: 'bytes=32768-', 'If-Range': original.headers.etag } });
  assert.equal(resumed.status, 200);
  assert.equal(resumed.headers['content-range'], undefined);
  assert.equal(resumed.body.length, original.body.length);
  assert.notEqual(resumed.headers.etag, original.headers.etag);
  assert.notDeepEqual(resumed.body, original.body);
});

test('weak If-Range validators do not authorize partial delivery', async t => {
  const lab = await setup(t);
  const full = await request(`${lab.url}/file`);
  const response = await request(`${lab.url}/file`, { headers: { Range: 'bytes=10-', 'If-Range': `W/${full.headers.etag}` } });
  assert.equal(response.status, 200);
});

test('server without range support returns 200 even if a range is requested', async t => {
  const lab = await setup(t);
  const result = await request(`${lab.url}/no-range`, { headers: { Range: 'bytes=10-20' } });
  assert.equal(result.status, 200);
  assert.equal(result.body.length, 65536);
  assert.equal(result.headers['accept-ranges'], 'none');
});

for (const path of ['/drop', '/short-body']) {
  test(`${path} is detected as an incomplete HTTP message`, async t => {
    const lab = await setup(t);
    await assert.rejects(request(`${lab.url}${path}`), error => error.code === 'ECONNRESET');
  });
}

test('incorrect Content-Range fixture actually contradicts requested offset', async t => {
  const lab = await setup(t);
  const result = await request(`${lab.url}/wrong-range`, { headers: { Range: 'bytes=100-199' } });
  assert.equal(result.status, 206);
  assert.equal(result.headers['content-range'], 'bytes 101-199/65536');
  assert.equal(result.body.length, 100);
});

test('slow fixture preserves the payload', async t => {
  const lab = await setup(t);
  const [normal, slow] = await Promise.all([request(`${lab.url}/file`), request(`${lab.url}/slow`)]);
  assert.deepEqual(slow.body, normal.body);
});

test('redirect, redirect loop and transient statuses are deterministic', async t => {
  const lab = await setup(t);
  for (const path of ['/redirect', '/loop']) {
    const result = await request(`${lab.url}${path}`);
    assert.equal(result.status, 302);
    assert.equal(result.headers.location, path === '/loop' ? '/loop' : '/file');
  }
  for (const status of [403, 404, 429, 500, 502, 503]) {
    const result = await request(`${lab.url}/status/${status}`);
    assert.equal(result.status, status);
    if ([429, 503].includes(status)) assert.equal(result.headers['retry-after'], '1');
  }
});

test('unknown routes, mutation methods and foreign browser origins are rejected', async t => {
  const lab = await setup(t);
  assert.equal((await request(`${lab.url}/missing`)).status, 404);
  assert.equal((await request(`${lab.url}/status/200`)).status, 400);
  assert.equal((await request(`${lab.url}/file`, { method: 'POST' })).status, 405);
  assert.equal((await request(`${lab.url}/file`, { headers: { Origin: 'https://untrusted.example' } })).status, 403);
  assert.equal((await request(`${lab.url}/file`, { headers: { Host: 'untrusted.example' } })).status, 403);
});

test('malformed request targets cannot crash the lab', async t => {
  const lab = await setup(t);
  assert.equal((await request(lab.url, { path: '//[' })).status, 400);
  assert.equal((await request(lab.url, { path: '//untrusted.example/file' })).status, 400);
  assert.equal((await request(`${lab.url}/file`)).status, 200);
});

test('an in-flight response preserves its version when the resource changes', async t => {
  const lab = await setup(t);
  const original = await request(`${lab.url}/file`);
  let signalChanged;
  const changed = new Promise(resolve => { signalChanged = resolve; });
  const inFlight = request(`${lab.url}/slow`, {
    onResponse: res => res.once('data', () => { lab.changeVersion(); signalChanged(); }),
  });
  // Attach both outcomes immediately, so failures never become unhandled rejections.
  const [oldResponse, newResponse] = await Promise.all([
    inFlight,
    changed.then(() => request(`${lab.url}/file`)),
  ]);
  assert.deepEqual(oldResponse.body, original.body);
  assert.equal(oldResponse.headers.etag, original.headers.etag);
  assert.notDeepEqual(newResponse.body, original.body);
  assert.notEqual(newResponse.headers.etag, original.headers.etag);
});

test('closing the lab terminates multiple active transfers and settles', { timeout: 3000 }, async t => {
  const lab = await startLab();
  let closing;
  t.after(() => closing ?? lab.close());
  let receiving = 0;
  const transfers = Array.from({ length: 3 }, () => request(`${lab.url}/slow`, {
    onResponse: res => res.once('data', () => {
      receiving += 1;
      if (receiving === 3) closing = lab.close();
    }),
  }));
  const results = await Promise.allSettled(transfers);
  assert.equal(receiving, 3);
  assert.ok(closing);
  await closing;
  for (const result of results) {
    assert.equal(result.status, 'rejected');
    assert.equal(result.reason.code, 'ECONNRESET');
  }
});
