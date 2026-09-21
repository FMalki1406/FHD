import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer, get } from 'node:https';
import { mkdtemp, realpath, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
const binary = process.env.FHD_TRANSFER_BIN ?? path.join(projectRoot, 'target', 'debug',
  process.platform === 'win32' ? 'fhd-transfer.exe' : 'fhd-transfer');

// No certificate or private key is written to disk or installed in a trust store.
const certificateScript = `
$ErrorActionPreference = 'Stop'
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
try {
  $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=localhost', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
  $san.AddDnsName('localhost')
  $san.AddIpAddress([System.Net.IPAddress]::Loopback)
  $request.CertificateExtensions.Add($san.Build())
  $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddHours(1))
  try {
    @{ cert = $certificate.ExportCertificatePem(); key = $rsa.ExportPkcs8PrivateKeyPem() } | ConvertTo-Json -Compress
  } finally { $certificate.Dispose() }
} finally { $rsa.Dispose() }
`;

function run(command, args, input = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let failure;
    const stop = message => {
      failure ??= new Error(message);
      child.kill('SIGKILL');
    };
    const deadline = setTimeout(() => stop('TLS test process exceeded its 15-second deadline'), 15_000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      stdout += chunk;
      if (stdout.length > 65_536) stop('TLS test process exceeded its output limit');
    });
    child.stderr.on('data', chunk => {
      stderr += chunk;
      if (stderr.length > 65_536) stop('TLS test process exceeded its output limit');
    });
    child.once('error', error => { failure = error; });
    child.once('close', code => {
      clearTimeout(deadline);
      if (failure) reject(failure);
      else resolve({ code, stdout, stderr });
    });
    child.stdin.on('error', error => {
      if (error.code !== 'EPIPE') stop('TLS test process could not receive its input');
    });
    child.stdin.end(input);
  });
}

function trustedProbe(url, certificate) {
  return new Promise((resolve, reject) => {
    // Trust only this ephemeral certificate; normal certificate and hostname checks remain on.
    const request = get(url, { ca: certificate, rejectUnauthorized: true, agent: false }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, body }));
      response.on('error', reject);
    });
    request.setTimeout(5_000, () => request.destroy(new Error('TLS fixture probe timed out')));
    request.on('error', reject);
  });
}

test('engine rejects an untrusted TLS certificate before sending HTTP or creating a job', async t => {
  const generated = await run(process.env.FHD_TEST_PWSH ?? 'pwsh', [
    '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand',
    Buffer.from(certificateScript, 'utf16le').toString('base64'),
  ]);
  // Do not include generator output in assertion diagnostics: it contains a transient private key.
  assert.equal(generated.code, 0, 'PowerShell 7 certificate generation must succeed');
  let credentials;
  try { credentials = JSON.parse(generated.stdout); }
  catch { throw new Error('Certificate generator returned invalid data'); }
  const parent = await realpath(await mkdtemp(path.join(tmpdir(), 'fhd-tls-')));
  const directory = path.join(parent, 'job');
  t.after(() => rm(parent, { recursive: true, force: true }));

  let connections = 0;
  let requests = 0;
  const sockets = new Set();
  const server = createServer(credentials, (_request, response) => {
    requests += 1;
    response.writeHead(200, { 'Content-Length': '7' });
    response.end('fixture');
  });
  server.on('connection', socket => {
    connections += 1;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  // A client certificate rejection is expected and must never become a fixture crash.
  server.on('tlsClientError', () => {});
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const url = `https://127.0.0.1:${server.address().port}/file`;
  assert.deepEqual(await trustedProbe(url, credentials.cert), { status: 200, body: 'fixture' });
  const connectionsBefore = connections;
  const requestsBefore = requests;
  const result = await run(binary, [directory, 'fixture.bin'], `${url}\n`);
  assert.equal(result.code, 2, 'untrusted TLS must fail the transfer');
  assert.ok(connections > connectionsBefore, 'the binary must actually connect to the TLS fixture');
  assert.equal(requests, requestsBefore, 'no HTTP request may cross the failed TLS handshake');
  assert.deepEqual(await readdir(parent), [], 'certificate rejection must create no download state');
  assert.doesNotMatch(result.stdout, /checkpoint=|completed/);
  assert.ok(!result.stderr.includes(url), 'diagnostics must not expose the input URL');
});
