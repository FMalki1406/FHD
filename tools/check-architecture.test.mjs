import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  attributesIn, checkArchitecture, checkReviewableSources, checkTestCoverage,
  unsafeOffendersIn, unusedAllowances, withoutComments,
} from './check-architecture.mjs';

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

  // An approved item that disappears is still reported -- by the check that can
  // see the tree, which is where that question moved. Asking it of a string a
  // caller passed in made every synthetic sample above answer it wrongly.
  assert.match(unusedAllowances(new Map([[file, []]]))[0], /no longer present/u);
  assert.deepEqual(unsafeOffendersIn(file, 'fn nothing() {}\n'), []);

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

// F1, twice reported. The first fix stripped comments before deciding what an
// attribute meant, but the attribute's own boundaries were found first, so
// `#[allow /* ] */ (unsafe_code)]` ended at the bracket inside the comment and
// came back as `#[allow /* ]` -- no mention of unsafe_code, dropped unexamined.
//
// The regression test missed it too, and that is the more useful lesson: it ran
// against the platform file, whose approved allowance was absent from the
// sample, so a "no longer present" complaint made the offender list non-empty
// and the assertion passed without the bypass ever being seen. A count of "any
// message" is not a diagnosis. These use a file with no approvals at all, so
// the only thing that can be reported is the thing under test, and they match
// the message rather than counting it.
test('unsafe gate is not talked past with a comment inside the attribute', () => {
  // A file with no approved allowance: any offender here is the one we want.
  const clean = 'crates/adapters/storage/src/lib.rs';
  const bypasses = [
    ['a block comment', '#[allow /* reason */ (unsafe_code)]\npub fn unauthorized() {}\n'],
    // Block comments nest in Rust, so a scan for the first `*/` stops early.
    ['nested block comments', '#[allow /* a /* b */ c */ (unsafe_code)]\npub fn unauthorized() {}\n'],
    ['a line comment', '#[allow( // why\n    unsafe_code\n)]\npub fn unauthorized() {}\n'],
    // The one that survived the first fix: the attribute's end was found
    // before its comments were removed.
    ['a bracket inside a comment', '#![deny(unsafe_code)]\n#[allow /* ] */ (unsafe_code)]\npub fn unauthorized() {}\n'],
    ['a bracket inside a line comment', '#[allow( // ]\n    unsafe_code\n)]\npub fn unauthorized() {}\n'],
    ['a bracket inside nested comments', '#[allow /* a /* ] */ b */ (unsafe_code)]\npub fn unauthorized() {}\n'],
  ];
  for (const [what, source] of bypasses) {
    const offenders = unsafeOffendersIn(clean, source);
    assert.equal(
      offenders.length, 1,
      `${what}: expected exactly one report, got ${JSON.stringify(offenders)}`,
    );
    assert.match(
      offenders[0],
      /unsafe allowed on an item that is not approved|spelling this gate does not accept/u,
      `${what}: reported something other than the allowance`,
    );
  }

  // Inner attributes stay refused, and for the stated reason.
  for (const inner of [
    '#![allow(unsafe_code)]\n',
    '#![allow /* reason */ (unsafe_code)]\n',
    '#![allow(dead_code, unsafe_code)]\n',
    '#![cfg_attr(windows, allow(unsafe_code))]\n',
  ]) {
    const offenders = unsafeOffendersIn(clean, inner);
    assert.equal(offenders.length, 1, inner);
    assert.match(offenders[0], /crate- or module-wide/u, inner);
  }

  // And a file that keeps every allowance it is entitled to reports nothing --
  // so the checks above are detecting the bypass, not the sample's tidiness.
  const platform = 'crates/adapters/platform/src/lib.rs';
  assert.deepEqual(
    unsafeOffendersIn(platform, '#[allow(unsafe_code)]\nfn our_uid() -> u32 {\n    0\n}\n'),
    [],
  );
  assert.deepEqual(
    unsafeOffendersIn(platform, '#[allow /* geteuid */ (unsafe_code)]\nfn our_uid() -> u32 {\n}\n'),
    [],
    'a comment explaining the approved allowance is still the approved allowance',
  );
  // The same file with the allowance moved off its approved item: one report,
  // about the item that is not approved.
  //
  // It used to be two, the second being the approved item "no longer present" --
  // but that question is about the tree, not about a string a caller passed in,
  // and asking it here made every synthetic sample answer it wrongly. It moved
  // to `unusedAllowances`, which is asked once after the real files are read,
  // and is asserted on its own below.
  const moved = unsafeOffendersIn(platform, '#[allow(unsafe_code)]\nfn somewhere_else() {}\n');
  assert.equal(moved.length, 1, JSON.stringify(moved));
  assert.match(moved[0], /is not approved/u);
});

// The list has to keep describing the tree, which is a question about the tree.
test('an approved allowance that no longer exists in the tree is reported', () => {
  const platform = 'crates/adapters/platform/src/lib.rs';
  // Nothing found at all: every approved entry for that file is reported.
  const none = unusedAllowances(new Map());
  assert.ok(none.length >= 1, JSON.stringify(none));
  assert.ok(none.every(one => /no longer present/u.test(one)), JSON.stringify(none));

  // Found once, approved twice -- which is the shape of a platform-specific
  // item with one implementation per system -- still reports the missing one.
  const linker =
    'pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {';
  const once = unusedAllowances(new Map([[platform, ['fn our_uid() -> u32 {', linker]]]));
  assert.equal(once.length, 1, JSON.stringify(once));
  assert.match(once[0], /link_into_directory/u);

  // And everything present reports nothing.
  assert.deepEqual(
    unusedAllowances(new Map([[platform, ['fn our_uid() -> u32 {', linker, linker]]])),
    [],
  );
});

test('a restriction is the policy, not a breach of it', () => {
  const clean = 'crates/adapters/storage/src/lib.rs';
  for (const restriction of [
    '#![forbid(unsafe_code)]\n',
    '#![deny(unsafe_code)]\n',
    '#![cfg_attr(not(windows), deny(unsafe_code))]\n',
  ]) {
    assert.deepEqual(unsafeOffendersIn(clean, restriction), [], restriction);
  }

  // A `/*` inside a string is not a comment, and a comment becomes one space
  // so tokens on either side of it never merge.
  assert.equal(withoutComments('#[doc = "/* not a comment */"]'), '#[doc = "/* not a comment */"]');
  assert.equal(withoutComments('a /* b */ c'), 'a   c');
  assert.equal(withoutComments('a // b\nc'), 'a  \nc');
  assert.equal(withoutComments('allow/*x*/(unsafe_code)'), 'allow (unsafe_code)');
});

// A raw NUL makes git diff a file as binary, so nothing in it is ever reviewed.
// This is the one check in the gate that had no test, while the commit adding it
// said it had been "tested against a planted one" -- true of a manual check, not
// of anything that would fail again. Both re-reviews said the same, and one of
// them showed the scope was narrower than the comment claimed: `crates` only,
// `.rs` only, so the gate's own source and the migrations' CHECK constraints
// were unprotected.
test('refuses a raw NUL in any reviewable source, whatever the tree or extension', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'fhd-gate-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const plant = (relative, bytes) => {
    const full = join(root, relative);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, bytes);
    return full;
  };

  // Clean to begin with, including a file whose NUL is written as an escape.
  plant('crates/a/src/lib.rs', 'fn main() { let _ = b"x\\x00y"; }\n');
  plant('tools/gate.mjs', 'export const x = 1;\n');
  assert.deepEqual(checkReviewableSources(root), []);

  // Every tree the gate walks, and extensions beyond Rust: a CHECK constraint
  // hidden in a migration is as unreviewable as a hidden policy in Rust.
  for (const relative of [
    'crates/a/src/lib.rs',
    'crates/adapters/persistence/migrations/005_x.sql',
    'tools/gate.mjs',
    '.github/workflows/engine.yml',
  ]) {
    plant(relative, Buffer.from(`ab\u0000cd`, 'binary'));
    const offenders = checkReviewableSources(root);
    assert.equal(offenders.length, 1, relative);
    assert.match(offenders[0], /raw NUL byte at offset 2/u);
    assert.ok(offenders[0].startsWith(relative), `${offenders[0]} should name ${relative}`);
    // Restored, so each iteration tests exactly one planted file.
    plant(relative, 'clean\n');
  }

  // A directory the gate must not walk into, and a file type it does not judge.
  plant('crates/a/target/debug/build.rs', Buffer.from('a\u0000b', 'binary'));
  plant('crates/a/fixture.bin', Buffer.from('a\u0000b', 'binary'));
  assert.deepEqual(checkReviewableSources(root), []);

  // A dangling symlink must be skipped, not throw and fail the gate with an
  // error about nothing. Creating one needs privileges on Windows, so the
  // assertion runs only where the link could actually be made.
  try {
    symlinkSync(join(root, 'crates/a/missing.rs'), join(root, 'crates/a/dangling.rs'));
  } catch {
    return;
  }
  assert.deepEqual(checkReviewableSources(root), []);
});
