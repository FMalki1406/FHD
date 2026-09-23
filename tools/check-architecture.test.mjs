import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkArchitecture, checkTestCoverage } from './check-architecture.mjs';

function metadata(graph) {
  const packages = Object.entries(graph).map(([name, dependencies]) => ({
    id: `path+file:///workspace/${name}#0.1.0`, name,
    dependencies: dependencies.map(dep => typeof dep === 'string' ? { name: dep, kind: null } : dep),
  }));
  return { packages, workspace_members: packages.map(pkg => pkg.id) };
}

test('accepts current legacy graph and pure migration bridge without permitting new legacy edges', () => {
  const graph = {
    'download-core': [], 'resume-policy': [], 'transfer-store': ['rusqlite', 'sha2'],
    'queue-secrets': ['zeroize'], 'platform-files': ['libc'],
    'download-engine': ['download-core', 'resume-policy', 'transfer-store', 'queue-secrets', 'platform-files', 'tokio'],
    'fhd-domain': ['resume-policy'], 'fhd-app': ['fhd-domain'],
    'fhd-testkit': ['fhd-app', 'fhd-domain', { name: 'tokio', kind: 'dev' }],
    'fhd-config': ['url'], 'fhd-telemetry': ['tracing', 'zeroize'],
  };
  assert.deepEqual(checkArchitecture(metadata(graph)), []);
  graph['fhd-app'].push('download-engine');
  graph['download-core'].push('transfer-store');
  assert.equal(checkArchitecture(metadata(graph)).length, 2);
});

test('composition root can assemble adapters but adapters cannot reference each other', () => {
  const graph = {
    'fhd-domain': [], 'fhd-app': ['fhd-domain'], 'fhd-runtime': ['fhd-app', 'fhd-domain'],
    'fhd-http': ['fhd-app', 'fhd-domain', 'reqwest'], 'fhd-storage': ['fhd-app', 'fhd-domain'],
    'fhd-daemon': ['fhd-runtime', 'fhd-http', 'fhd-storage'],
  };
  assert.deepEqual(checkArchitecture(metadata(graph)), []);
  graph['fhd-http'].push('fhd-storage');
  assert.match(checkArchitecture(metadata(graph))[0], /fhd-http -> fhd-storage.*forbidden/);
});

test('forbidden dependency cannot hide behind alias, target, optional, or dependency kind', () => {
  for (const kind of [null, 'normal', 'dev', 'build']) {
    const graph = metadata({
      'fhd-app': [{ name: 'fhd-http', rename: 'transport', kind, target: 'cfg(windows)', optional: true }],
      'fhd-http': [],
    });
    const violations = checkArchitecture(graph);
    assert.equal(violations.length, 1);
    assert.match(violations[0], /fhd-app -> fhd-http.*target=cfg\(windows\).*alias=transport/);
  }
});

test('domain rejects all unapproved external dependencies including unknown I/O libraries', () => {
  for (const name of ['tokio', 'reqwest', 'rusqlite', 'hypothetical-new-io']) {
    for (const kind of [null, 'dev', 'build']) {
      const violations = checkArchitecture(metadata({
        'fhd-domain': [{ name, kind, rename: 'pure_math', target: 'cfg(unix)' }],
      }));
      assert.equal(violations.length, 1);
      assert.match(violations[0], /not approved for pure domain/);
    }
  }
});

test('domain permits explicitly approved pure dependencies and test-only property tests', () => {
  assert.deepEqual(checkArchitecture(metadata({
    'fhd-domain': ['serde', 'thiserror', { name: 'proptest', kind: 'dev' }],
  })), []);
  assert.equal(checkArchitecture(metadata({ 'fhd-domain': ['proptest'] })).length, 1);
  assert.equal(checkArchitecture(metadata({ 'fhd-domain': [{ name: 'serde', kind: 'build' }] })).length, 1);
});

test('testkit is dev-only and cannot invert domain dependencies', () => {
  for (const kind of [null, 'build']) {
    assert.equal(checkArchitecture(metadata({
      'fhd-http': [{ name: 'fhd-testkit', kind }], 'fhd-testkit': [],
    })).length, 1);
  }
  assert.deepEqual(checkArchitecture(metadata({
    'fhd-http': [{ name: 'fhd-testkit', kind: 'dev' }], 'fhd-testkit': [],
  })), []);
  assert.equal(checkArchitecture(metadata({
    'fhd-domain': [{ name: 'fhd-testkit', kind: 'dev' }], 'fhd-testkit': [],
  })).length, 1);
});

test('new unclassified workspace packages and unclassified fhd dependencies fail closed', () => {
  for (const name of ['fhd-surprise', 'helper', 'constructor']) {
    assert.match(checkArchitecture(metadata({ [name]: [] }))[0], /unclassified workspace/);
  }
  assert.match(checkArchitecture(metadata({ 'fhd-app': ['fhd-unreviewed'] }))[0], /forbidden/);
});

test('rejects incomplete or malformed metadata instead of silently skipping members', () => {
  for (const broken of [{}, { packages: [], workspace_members: [] },
    { packages: [], workspace_members: ['missing'] }]) {
    assert.throws(() => checkArchitecture(broken));
  }
  const broken = metadata({ 'fhd-domain': [{ name: 'tokio', kind: 'mystery' }] });
  assert.throws(() => checkArchitecture(broken), /Invalid dependency/);
  const duplicate = metadata({ 'fhd-domain': [] });
  duplicate.workspace_members.push(duplicate.workspace_members[0]);
  assert.throws(() => checkArchitecture(duplicate), /Duplicate workspace/);
});

test('a workspace member no test step names is reported rather than shipping untested', () => {
  const metadata = {
    packages: [
      { id: 'a 0.1.0', name: 'fhd-domain', dependencies: [] },
      { id: 'b 0.1.0', name: 'fhd-newcomer', dependencies: [] },
    ],
    workspace_members: ['a 0.1.0', 'b 0.1.0'],
  };
  const workflow = [
    '      - name: Test domain',
    '        run: cargo +1.98.1 test -p fhd-domain --locked',
  ].join('\n');
  assert.deepEqual(checkTestCoverage(metadata, workflow), [
    'fhd-newcomer: no test step in the workflow names this package',
  ]);
  const covered = `${workflow}\n        run: cargo +1.98.1 test -p fhd-newcomer --locked`;
  assert.deepEqual(checkTestCoverage(metadata, covered), []);
});
