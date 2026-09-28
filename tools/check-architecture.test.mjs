import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  checkArchitecture, checkReviewableSources, checkTestCoverage,
  doubleEncodedText, shellEscapeWreckage,
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
    // A third review widened the scan, and these are its examples. `Cargo.lock`
    // and the pinned toolchain are where hiding a change pays best; `docs/` is
    // where the mojibake damage actually happened; and `tools/rust.ps1` -- the
    // wrapper whose shell caused all three damages -- was exempt from the rule
    // named after PowerShell strings, because `.ps1` was not in the list.
    'Cargo.lock',
    'rust-toolchain.toml',
    'package.json',
    'docs/publication-contract.md',
    'tools/rust.ps1',
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

  // The root is scanned without descending. `.tools/` holds this project's
  // pinned Rust toolchain -- thousands of files it neither owns nor tracks -- and
  // recursing from the root would walk all of it. So a file in an unnamed
  // directory is out of scope, while the root's own files are in it.
  plant('.tools/rustup/toolchains/1.98.1/lib/rustlib/src/core/src/lib.rs',
    Buffer.from('a\u0000b', 'binary'));
  assert.deepEqual(checkReviewableSources(root), []);
  plant('Cargo.toml', Buffer.from('a\u0000b', 'binary'));
  assert.equal(checkReviewableSources(root).length, 1);
  plant('Cargo.toml', '[workspace]\n');

  // Each file is judged once, though the root entry and a named tree could both
  // reach it if the root ever started recursing.
  plant('docs/twice.md', Buffer.from('a\u0000b', 'binary'));
  assert.equal(checkReviewableSources(root).length, 1);
  plant('docs/twice.md', 'clean\n');

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

// Planted, because both of these really happened in this tree and neither was
// caught by anything: the carriage return stopped the gate parsing, and the
// literal backtick-n compiled, shipped, and was found by eye afterwards.
test('refuses what a PowerShell string edit leaves behind', () => {
  const clean = [
    'let x = 1;\r\n// a CRLF file is fine\r\n',
    'let y = 2;\n// so is an LF file\n',
    // The escapes as closed one-letter code spans, which is how prose refers to
    // them. Rejecting these would make the rule unusable in its own comment.
    '// PowerShell writes `n` and `r`, and Rust writes `\\n`.\n',
    // A backtick span that merely starts with one of the letters.
    '// `nothing here` and `renameatx_np` are ordinary spans.\n',
  ];
  for (const text of clean) {
    assert.deepEqual(shellEscapeWreckage('a.rs', Buffer.from(text, 'binary')), [], text);
  }

  // A bare CR: to a JavaScript parser the comment ends there and `code` is code.
  const bare = shellEscapeWreckage('a.mjs', Buffer.from('// a comment\rcode();\n', 'binary'));
  assert.equal(bare.length, 1, JSON.stringify(bare));
  assert.match(bare[0], /carriage return at offset 12 with no newline/u);
  assert.ok(bare[0].startsWith('a.mjs'));

  // The literal escape where a line break was meant, for each letter.
  for (const letter of ['n', 'r', 't', '0']) {
    const text = `// first\`${letter}        // second\n`;
    const found = shellEscapeWreckage('a.rs', Buffer.from(text, 'binary'));
    assert.equal(found.length, 1, `${letter}: ${JSON.stringify(found)}`);
    assert.match(found[0], new RegExp(`\`${letter} at offset 8`, 'u'));
  }

  // And the exact shape that shipped: the escape followed by spaces, inside a
  // Rust comment, in a file that is otherwise CRLF.
  //
  // The backtick comes from a char code because the gate walks `tools/`: a
  // fixture spelled literally here would make this file an offender and fail the
  // gate on its own test data. The bytes handed to the rule are identical.
  const tick = String.fromCharCode(0x60);
  const shipped = `        // because Path::components${tick}n        // normalises: it\r\n`;
  assert.equal(shellEscapeWreckage('lib.rs', Buffer.from(shipped, 'binary')).length, 1);

  // The shape the first version missed, and the commoner one: the escape with no
  // whitespace after it. The instance that shipped was caught only because the
  // next line happened to be indented.
  for (const text of [
    `// because Path::components${tick}nnormalises\n`,
    `let s = "a${tick}nb";\n`,
    `// at the end of the file${tick}n`,
  ]) {
    assert.equal(shellEscapeWreckage('a.rs', Buffer.from(text, 'binary')).length, 1, text);
  }

  // Every PowerShell escape letter, not the four that happened to bite us. A
  // literal backtick-e leaves a raw ESC, as invisible as the NUL byte the
  // sibling rule exists for.
  for (const letter of [...'0abefnrtv']) {
    const text = `// first${tick}${letter}second\n`;
    assert.equal(shellEscapeWreckage('a.rs', Buffer.from(text, 'binary')).length, 1, letter);
  }

  // A Markdown fence with a language tag puts an escape letter straight after a
  // backtick with nothing closing it on that line. Widening to unclosed spans
  // made every fenced block in `docs/` an offender, which is how this exception
  // came to be measured rather than guessed.
  for (const tag of ['text', 'rust', 'bash', 'none', 'toml', 'powershell']) {
    const fence = `${tick}${tick}${tick}${tag}\nbody\n${tick}${tick}${tick}\n`;
    assert.deepEqual(shellEscapeWreckage('a.md', Buffer.from(fence, 'binary')), [], tag);
  }

  // A *closing* backtick with an English suffix after it: an escape letter
  // follows and nothing closes it on the line. The rule flagged this in its own
  // crate's comments, so only odd-numbered backticks on a line can open a span.
  for (const prose of [
    `// it exists to be ${tick}fstat${tick}ed and compared\n`,
    `// the ${tick}Moved${tick}ness of it\n`,
    `/// ${tick}O_PATH${tick}, then ${tick}fstat${tick}ted\n`,
  ]) {
    assert.deepEqual(shellEscapeWreckage('a.rs', Buffer.from(prose, 'binary')), [], prose);
  }

  // And the shape that shipped is still caught, though its backtick also has a
  // word character before it: it is the only backtick on its line, so it opens.
  const alone = `        // because Path::components${tick}n        // normalises\n`;
  assert.equal(shellEscapeWreckage('a.rs', Buffer.from(alone, 'binary')).length, 1);

  // Several strays on one line must not report **none**. A parity rule written to
  // fix the closing-backtick false positive did exactly that for every even
  // count, which an engineering review measured as a regression against the
  // version before it: with two strays, the first one's scan finds the second and
  // calls the span closed, and the second is skipped as a closing backtick.
  // Reporting the first is enough -- the gate refuses the file either way --
  // but reporting zero is not, and a collapsed block produces several per line.
  for (const count of [1, 2, 3, 4]) {
    let line = '// ';
    for (let at = 0; at < count; at += 1) line += `x${tick}n  ${at}`;
    assert.ok(
      shellEscapeWreckage('a.rs', Buffer.from(`${line}\n`, 'binary')).length >= 1,
      `${count} strays on one line reported nothing`,
    );
  }

  // A stray with no whitespace after it at all, which the first version missed.
  const tight = `// because Path::components${tick}nnormalises\n`;
  assert.equal(shellEscapeWreckage('a.rs', Buffer.from(tight, 'binary')).length, 1);

  // U+2028 and U+2029 end a line for a JavaScript parser exactly as the CR does,
  // so a comment holding one stops being a comment. Judged only where a
  // JavaScript parser reads the file.
  // From char codes, not literals: this file is a `.mjs` the gate scans, so
  // spelling them out would make the test data an offender.
  for (const separator of [String.fromCharCode(0x2028), String.fromCharCode(0x2029)]) {
    const text = `// a comment${separator}code();\n`;
    assert.equal(shellEscapeWreckage('a.mjs', Buffer.from(text, 'utf8')).length, 1, separator);
    assert.deepEqual(shellEscapeWreckage('a.rs', Buffer.from(text, 'utf8')), [], separator);
  }
});

// The first of the three PowerShell damages, and the one that was still in the
// tree: `docs/development.md` had written the hazard down while eight
// occurrences sat in three source files, five of them in the first four lines of
// the crate under review. Nothing checked for it until a security review counted
// them by hand.
test('refuses text that has been decoded twice', () => {
  // The real bytes, as hex: the section sign, and an Arabic letter, each read as
  // Latin-1 and re-encoded. Written as bytes rather than characters for the same
  // reason as the backtick above -- the gate scans this file.
  const section = Buffer.from('c382c2a7', 'hex');       // from C2 A7
  const arabic = Buffer.from('c398c2af', 'hex');        // from D8 AF
  for (const damaged of [section, arabic]) {
    const text = Buffer.concat([Buffer.from('//! section '), damaged, Buffer.from('4 allows\n')]);
    const found = doubleEncodedText('lib.rs', text);
    assert.equal(found.length, 1, damaged.toString('hex'));
    assert.match(found[0], /decoded twice at offset 12/u);
  }

  // Adjacent Latin-1 supplement characters are legal text, so the rule names the
  // leads rather than the range. This is the sequence that refuted the first
  // version: the multiplication sign followed by a closing Arabic quote, from
  // `docs/status-report-2026-09-23.md`.
  const legitimate = Buffer.concat([
    Buffer.from('15'), Buffer.from('c397c2bb', 'hex'), Buffer.from(' and more\n'),
  ]);
  assert.deepEqual(doubleEncodedText('a.md', legitimate), []);

  // Undamaged Arabic and an undamaged section sign both pass.
  assert.deepEqual(doubleEncodedText('a.md', Buffer.from('§4 يسمح\n', 'utf8')), []);
});
