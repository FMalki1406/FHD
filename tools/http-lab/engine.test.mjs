import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeFixture, startLab } from './server.mjs';

const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
const binary = process.env.FHD_TRANSFER_BIN ?? path.join(projectRoot, 'target', 'debug',
  process.platform === 'win32' ? 'fhd-transfer.exe' : 'fhd-transfer');
const expected = makeFixture();
const digest = createHash('sha256').update(expected).digest('hex');

async function setup(t) {
  const parent = await mkdtemp(path.join(tmpdir(), 'fhd-integration-'));
  const directory = path.join(parent, 'job');
  t.after(() => rm(parent, { recursive: true, force: true }));
  const lab = await startLab();
  t.after(() => lab.close());
  return { directory, lab, output: path.join(directory, 'fixture.bin') };
}

function transfer(directory, url, { sha256 = digest, killAtCheckpoint = false, outputName = 'fixture.bin', extraArgs = [] } = {}) {
  return new Promise((resolve, reject) => {
    const args = [directory, outputName, '--allow-http', '--checkpoint-bytes', '16384', ...extraArgs];
    if (sha256) args.push('--sha256', sha256);
    const child = spawn(binary, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let killed = false;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, 15_000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      stdout += chunk;
      if (killAtCheckpoint && !killed && /checkpoint=[1-9]\d*\r?\n/.test(stdout)) {
        killed = child.kill('SIGKILL');
      }
    });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        reject(new Error('Transfer process exceeded the integration deadline'));
        return;
      }
      resolve({ code, signal, stdout, stderr, killed });
    });
    // An early validation failure can close stdin before it has been written.
    child.stdin.on('error', error => { if (error.code !== 'EPIPE') reject(error); });
    child.stdin.end(`${url}\n`);
  });
}

async function partSnapshot(directory) {
  const names = (await readdir(directory)).filter(name => name.endsWith('.part'));
  assert.equal(names.length, 1, 'exactly one partial file should survive the interruption');
  return readFile(path.join(directory, names[0]));
}

async function assertNoOutput(output) {
  await assert.rejects(readFile(output), { code: 'ENOENT' });
}

function assertComplete(result, resumed) {
  assert.equal(result.code, 0, result.stderr);
  const match = /completed bytes=65536 resumed_from=(\d+)/.exec(result.stdout);
  assert.ok(match, result.stdout);
  assert.equal(Number(match[1]) > 0, resumed);
}

test('engine downloads and verifies the complete fixture', async t => {
  const { directory, lab, output } = await setup(t);
  assertComplete(await transfer(directory, `${lab.url}/file`), false);
  assert.deepEqual(await readFile(output), expected);
});

test('CLI applies byte rate and rejects invalid rates before creating state', async t => {
  const { directory, lab, output } = await setup(t);
  for (const rate of ['0', '1073741825', 'invalid']) {
    const rejected = await transfer(directory, `${lab.url}/file`, { extraArgs: ['--bytes-per-second', rate] });
    assert.equal(rejected.code, 2);
    await assert.rejects(stat(directory), { code: 'ENOENT' });
  }
  const start = performance.now();
  const result = await transfer(directory, `${lab.url}/file`, { extraArgs: ['--bytes-per-second', '65536'] });
  assertComplete(result, false);
  assert.ok(performance.now() - start >= 950, 'body must be paced through completion');
  assert.deepEqual(await readFile(output), expected);
});

test('engine persists URL fingerprints and rejects a different query on resume', async t => {
  const { directory, lab, output } = await setup(t);
  const secret = 'synthetic-url-secret-4c183ec2';
  const url = `${lab.url}/drop-once?token=${secret}`;
  const first = await transfer(directory, url);
  assert.equal(first.code, 2);
  const before = await partSnapshot(directory);
  const mismatch = await transfer(directory, `${url}-changed`);
  assert.equal(mismatch.code, 2);
  assert.match(mismatch.stderr, /LocalStateMismatch/);
  assert.deepEqual(await partSnapshot(directory), before);
  await assertNoOutput(output);
  assertComplete(await transfer(directory, url), true);
  for (const name of await readdir(directory)) {
    assert.ok(!(await readFile(path.join(directory, name))).includes(Buffer.from(secret)),
      'URL sentinel must not appear in persisted job files');
  }
  assert.ok(!first.stderr.includes(secret) && !first.stdout.includes(secret));
});

test('engine follows a redirect and preserves the verified representation', async t => {
  const { directory, lab, output } = await setup(t);
  assertComplete(await transfer(directory, `${lab.url}/redirect`), false);
  assert.deepEqual(await readFile(output), expected);
});

test('engine resumes a durable checkpoint after a dropped connection', async t => {
  const { directory, lab, output } = await setup(t);
  assert.equal((await transfer(directory, `${lab.url}/drop-once`)).code, 2);
  await assertNoOutput(output);
  const partial = await partSnapshot(directory);
  assert.ok(partial.length >= 16384 && partial.length < expected.length);
  assert.deepEqual(partial, expected.subarray(0, partial.length));
  assertComplete(await transfer(directory, `${lab.url}/drop-once`), true);
  assert.deepEqual(await readFile(output), expected);
});

for (const route of ['/changed-once', '/wrong-range-once', '/no-range-once']) {
  test(`engine refuses unsafe recovery from ${route} without appending bytes`, async t => {
    const { directory, lab, output } = await setup(t);
    assert.equal((await transfer(directory, `${lab.url}${route}`)).code, 2);
    const before = await partSnapshot(directory);
    assert.ok(before.length >= 16384);
    assert.equal((await transfer(directory, `${lab.url}${route}`)).code, 2);
    assert.deepEqual(await partSnapshot(directory), before);
    await assertNoOutput(output);
  });
}

test('engine refuses to overwrite an unrelated destination', async t => {
  const { directory, lab, output } = await setup(t);
  assert.equal((await transfer(directory, `${lab.url}/drop-once`)).code, 2);
  const existing = Buffer.from('unrelated user content');
  await writeFile(output, existing);
  const result = await transfer(directory, `${lab.url}/drop-once`);
  assert.equal(result.code, 2);
  assert.equal(result.stderr.trim(), 'DestinationConflict');
  assert.deepEqual(await readFile(output), existing);
});

test('engine reports corrupted durable bytes without modifying them', async t => {
  const { directory, lab, output } = await setup(t);
  assert.equal((await transfer(directory, `${lab.url}/drop-once`)).code, 2);
  const bytes = await partSnapshot(directory);
  bytes[0] ^= 0xff;
  await writeFile(path.join(directory, 'payload.part'), bytes);
  const result = await transfer(directory, `${lab.url}/drop-once`);
  assert.equal(result.code, 2);
  assert.equal(result.stderr.trim(), 'StoredDataCorrupt');
  assert.deepEqual(await partSnapshot(directory), bytes);
  await assertNoOutput(output);
});

test('engine recovers after forced process termination at a durable checkpoint', async t => {
  const { directory, lab, output } = await setup(t);
  const interrupted = await transfer(directory, `${lab.url}/slow`, { killAtCheckpoint: true });
  assert.equal(interrupted.killed, true, interrupted.stdout);
  assert.notEqual(interrupted.code, 0);
  await assertNoOutput(output);
  assertComplete(await transfer(directory, `${lab.url}/slow`), true);
  assert.deepEqual(await readFile(output), expected);
});

test('engine does not publish bytes that fail the expected digest', async t => {
  const { directory, lab, output } = await setup(t);
  const result = await transfer(directory, `${lab.url}/file`, { sha256: '0'.repeat(64) });
  assert.equal(result.code, 2);
  assert.equal(result.stderr.trim(), 'ChecksumMismatch');
  await assertNoOutput(output);
});

test('engine downloads from a server that does not support ranges', async t => {
  const { directory, lab, output } = await setup(t);
  assertComplete(await transfer(directory, `${lab.url}/no-range`), false);
  assert.deepEqual(await readFile(output), expected);
});

test('engine rejects an oversized representation before creating a job directory', async t => {
  const { directory, lab, output } = await setup(t);
  assert.equal((await transfer(directory, `${lab.url}/file`, { extraArgs: ['--max-bytes', '100'] })).code, 2);
  await assert.rejects(stat(directory), { code: 'ENOENT' });
  await assertNoOutput(output);
});

test('engine rejects a changed output filename on recovery without modifying the partial file', async t => {
  const { directory, lab, output } = await setup(t);
  assert.equal((await transfer(directory, `${lab.url}/drop-once`)).code, 2);
  const before = await partSnapshot(directory);
  assert.equal((await transfer(directory, `${lab.url}/drop-once`, { outputName: 'different.bin' })).code, 2);
  assert.deepEqual(await partSnapshot(directory), before);
  await assertNoOutput(output);
  await assertNoOutput(path.join(directory, 'different.bin'));
});

test('engine retains the original output binding after a task has completed', async t => {
  const { directory, lab, output } = await setup(t);
  assertComplete(await transfer(directory, `${lab.url}/file`), false);
  assert.equal((await transfer(directory, `${lab.url}/file`, { outputName: 'different.bin' })).code, 2);
  assert.deepEqual(await readFile(output), expected);
  await assertNoOutput(path.join(directory, 'different.bin'));
});

test('engine validates connection bounds and accepts parallel fallback for small files', async t => {
  const { directory, lab, output } = await setup(t);
  for (const count of ['0', '9']) {
    const result = await transfer(directory, `${lab.url}/file`, { extraArgs: ['--connections', count] });
    assert.equal(result.code, 2);
    await assert.rejects(stat(directory), { code: 'ENOENT' });
  }
  assertComplete(await transfer(directory, `${lab.url}/file`, { extraArgs: ['--connections', '4'] }), false);
  assert.deepEqual(await readFile(output), expected);
});
