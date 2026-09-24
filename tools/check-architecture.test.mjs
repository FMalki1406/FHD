import { test } from 'node:test';
import assert from 'node:assert/strict';
import { attributesIn, checkArchitecture, checkTestCoverage, unsafeOffendersIn } from './check-architecture.mjs';

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

// R3 from the review of 2026-09-24: the gate matched a line prefix, so every
// other spelling the compiler accepts walked past it. These are the spellings
// the review demonstrated, plus the ones that search turned up.
test('unsafe gate catches every spelling that can permit unsafe, not one prefix', () => {
  const file = 'crates/adapters/platform/src/lib.rs';
  const approved = '#[allow(unsafe_code)]\nfn our_uid() -> u32 {\n    0\n}\n';
  // The approved spelling on the approved item is the baseline.
  assert.deepEqual(unsafeOffendersIn(file, approved), []);

  const bypasses = [
    // A list: silences the lint just as well as the single form.
    '#[allow(dead_code, unsafe_code)]\nfn our_uid() -> u32 { 0 }\n',
    // Conditional: applies on the platform it names.
    '#[cfg_attr(unix, allow(unsafe_code))]\nfn our_uid() -> u32 { 0 }\n',
    // Split across lines: a line-based scan never saw the whole attribute.
    '#[allow(\n    unsafe_code\n)]\nfn our_uid() -> u32 { 0 }\n',
    // `expect` silences a deny exactly like `allow`, and was missed entirely.
    '#[expect(unsafe_code)]\nfn our_uid() -> u32 { 0 }\n',
    // Whitespace inside the approved form is still a different spelling.
    '#[ allow( unsafe_code ) ]\nfn our_uid() -> u32 { 0 }\n',
  ];
  for (const source of bypasses) {
    const offenders = unsafeOffendersIn(file, source);
    // The property is that nothing which permits unsafe goes unreported, by
    // whichever of the two routes fits: a spelling the gate will not accept,
    // or the approved spelling on an item nobody approved. Each of these
    // returned an empty list before, which is what made them bypasses.
    assert.ok(
      offenders.some(one =>
        /spelling this gate does not accept|is not approved/u.test(one)),
      `not reported: ${JSON.stringify(source)} -> ${JSON.stringify(offenders)}`,
    );
  }

  // Crate- and module-wide allowances stay refused in every spelling.
  for (const inner of [
    '#![allow(unsafe_code)]\n',
    '#![allow(dead_code, unsafe_code)]\n',
    '#![cfg_attr(windows, allow(unsafe_code))]\n',
  ]) {
    const offenders = unsafeOffendersIn(file, inner);
    assert.ok(offenders.some(one => one.includes('crate- or module-wide')), inner);
  }

  // The policy's own attributes are not allowances and must not be reported.
  for (const restriction of [
    `#![forbid(unsafe_code)]\n${approved}`,
    `#![cfg_attr(not(windows), deny(unsafe_code))]\n${approved}`,
    `#![deny(unsafe_code)]\n${approved}`,
  ]) {
    assert.deepEqual(unsafeOffendersIn(file, restriction), [], restriction);
  }

  // An approved item that disappears is still reported, as before.
  assert.match(unsafeOffendersIn(file, 'fn nothing() {}\n')[0], /no longer present/u);

  // A file with no approvals may not allow unsafe at all.
  assert.match(
    unsafeOffendersIn('crates/adapters/storage/src/lib.rs', approved)[0],
    /not approved/u,
  );
});

// A `]` inside a string must not end an attribute early, or the rest of it --
// including an allowance -- would be read as ordinary code.
test('attribute scanning survives brackets inside string literals', () => {
  const [attribute] = attributesIn('#[doc = "a ] bracket"]\nfn f() {}');
  assert.equal(attribute.text, '#[doc = "a ] bracket"]');
  assert.equal(
    unsafeOffendersIn('crates/adapters/storage/src/lib.rs', '#[doc = "]"]\n#[allow(unsafe_code)]\nfn f() {}').length,
    1,
  );
});
