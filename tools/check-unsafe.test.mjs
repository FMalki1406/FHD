import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  APPROVED, auditFailed, auditFile, EXPANSION_LIMIT, exportedMacros, findings, itemBelow,
  resolveCargo, siteKey, sitesFrom, targetsFrom, unaudited, unauditableTargets,
} from './check-unsafe.mjs';

/// The compiler these tests put their samples to.
///
/// The project keeps Rust under `.tools/` so a machine's own installation is untouched
/// (`docs/development.md`), and CI installs it on PATH. **A missing compiler fails the
/// test rather than skipping it**: a sample nobody compiled is not evidence, and a
/// skipped test reads as a passing one in every summary that matters.
function resolveRustc() {
  const candidates = [
    process.env.RUSTC,
    join(process.cwd(), '.tools', 'cargo', 'bin', process.platform === 'win32' ? 'rustc.exe' : 'rustc'),
    'rustc',
  ].filter(Boolean);
  for (const candidate of candidates) {
    const found = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (!found.error && found.status === 0) return candidate;
  }
  return assert.fail(`no rustc found; tried ${candidates.join(', ')}`);
}

const unsafeBody = 'unsafe { core::ptr::read(&7u32 as *const u32) }';

/// Every spelling that ever got past the scanner this gate replaces, put to rustc.
///
/// **Each of these was a defect, found by review, one at a time.** An item on the
/// attribute's own line; whitespace between `#` and `[`; a raw string holding a quote
/// and then a `]`; an ordinary string spanning two lines; a raw string with more hashes
/// than the scan looked at. Five rounds, five special cases, one cause: a hand-written
/// lexer reading text where the compiler reads tokens.
///
/// They are kept here, all together, as samples rather than as lexer cases -- because
/// what answers them now is the compiler. Every one compiles (so it is Rust somebody
/// could really write) and every one must be enumerated. The crate denies unsafe at its
/// root and the body uses `unsafe`, so a sample that compiles at all is one whose
/// attribute genuinely silenced the lint: that is what makes it a bypass rather than a
/// curiosity.
test('every spelling that once got past the scanner is enumerated by the compiler', () => {
  const rustc = resolveRustc();
  const fifty = '#'.repeat(50);
  const samples = [
    ['the plain form', '#[allow(unsafe_code)]'],
    ['an item on the attribute line', '#[allow(unsafe_code)] pub fn also() -> u32 { 1 }\n'],
    ['a space between the tokens', '# [allow(unsafe_code)]'],
    ['a newline between the tokens', '#\n[allow(unsafe_code)]'],
    ['a comment between the tokens', '# /* why */ [allow(unsafe_code)]'],
    ['expect rather than allow', '#[expect(unsafe_code)]'],
    ['behind cfg_attr', '#[cfg_attr(all(), allow(unsafe_code))]'],
    ['after a raw string holding a quote and a bracket', '#[doc = r#"a"b]"#]\n#[allow(unsafe_code)]'],
    ['after a string that spans two lines', 'pub fn s() -> &\'static str { "a\nb" }\n#[allow(unsafe_code)]'],
    [`after a raw string with fifty hashes`, `#[doc = r${fifty}"a ] here"${fifty}]\n#[allow(unsafe_code)]`],
  ];
  const base = mkdtempSync(join(tmpdir(), 'fhd-unsafe-samples-'));
  try {
    for (const [name, attribute] of samples) {
      const file = join(base, `${name.replaceAll(/\W+/gu, '_')}.rs`);
      writeFileSync(
        file,
        `#![deny(unsafe_code)]\n${attribute}\npub fn f() -> u32 { ${unsafeBody} }\n`,
        'utf8',
      );
      const { sites, reasons } = auditFile(rustc, file);
      assert.deepEqual(reasons, [], `${name}: the sample must compile, or it proves nothing`);
      const allowances = sites.filter((site) => site.kind === 'allowance');
      assert.ok(
        allowances.length >= 1,
        `${name}: the compiler did not report an allowance, so this spelling is invisible`,
      );
      assert.ok(
        sites.some((site) => site.kind === 'usage'),
        `${name}: the use of unsafe was not reported either`,
      );
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

/// And valid Rust that merely looks like an allowance is not one.
///
/// The other direction of the same defect: `r"# [allow(unsafe_code)]"` in ordinary code
/// was read *as* an attribute and refused. A gate that rejects sound code buys nothing.
test('a literal that looks like an allowance is not reported', () => {
  const rustc = resolveRustc();
  const base = mkdtempSync(join(tmpdir(), 'fhd-unsafe-innocent-'));
  try {
    for (const [name, body] of [
      ['a raw string', 'pub fn f() -> &\'static str { r"# [allow(unsafe_code)]" }'],
      ['a raw string with hashes', 'pub fn f() -> &\'static str { r##"#[allow(unsafe_code)]"## }'],
      ['an ordinary string', 'pub fn f() -> &\'static str { "#[allow(unsafe_code)]" }'],
      ['a comment', '// #[allow(unsafe_code)]\npub fn f() -> u32 { 1 }'],
      ['a deny, which is the policy itself', '#![deny(unsafe_code)]\npub fn f() -> u32 { 1 }'],
      ['a forbid', '#![forbid(unsafe_code)]\npub fn f() -> u32 { 1 }'],
    ]) {
      const file = join(base, `${name.replaceAll(/\W+/gu, '_')}.rs`);
      writeFileSync(file, `${body}\n`, 'utf8');
      const { sites, reasons } = auditFile(rustc, file);
      assert.deepEqual(reasons, [], `${name}: the sample must compile`);
      assert.deepEqual(sites, [], `${name}: sound code was reported as permitting unsafe`);
    }
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

/// Two uses on one line are two uses.
///
/// **A line is not a site.** The key that identified a site was the file and the line, so
/// two `unsafe` blocks written on one line folded into one: the file counted one use
/// where the compiler had reported two, and a block added beside an existing one changed
/// no number at all -- in the very count that exists to make adding one a decision. A
/// security review proved it with the two diagnostics, and this is those two diagnostics.
///
/// The compiler is asked, because the claim is about what it reports; the deduplication
/// is then asserted on the same shape, since the real gate sees each site from several
/// invocations of the same file.
test('two uses of unsafe on one line are counted as two', () => {
  const rustc = resolveRustc();
  const base = mkdtempSync(join(tmpdir(), 'fhd-unsafe-one-line-'));
  try {
    const file = join(base, 'pair.rs');
    // Two blocks, one line, one allowance over them.
    writeFileSync(
      file,
      [
        '#![deny(unsafe_code)]',
        '#[allow(unsafe_code)]',
        `pub fn two() -> u32 { let a = ${unsafeBody}; let b = ${unsafeBody}; a + b }`,
        '',
      ].join('\n'),
      'utf8',
    );
    const { sites, reasons } = auditFile(rustc, file);
    assert.deepEqual(reasons, [], 'the sample must compile, or it proves nothing');
    const uses = sites.filter((site) => site.kind === 'usage');
    assert.equal(uses.length, 2, `the compiler reported ${uses.length} use(s): ${JSON.stringify(uses)}`);
    assert.equal(uses[0].line, uses[1].line, 'the premise failed: they are not on one line');
    assert.notEqual(uses[0].column, uses[1].column, 'the two have the same column');
    assert.notEqual(uses[0].offset, uses[1].offset, 'the two have the same byte offset');

    // And the key the gate itself deduplicates by keeps them apart, while still folding
    // the same site reported by two invocations into one. `siteKey` is the gate's own
    // function, not a copy of it: a first version of this test computed the key here, so
    // a mutation that put the line back in the real key passed unnoticed.
    assert.equal(new Set(uses.map(siteKey)).size, 2, 'the two uses share a key');

    // And the same file compiled a second time folds into the same two sites. This is the
    // property the gate depends on -- it sees every file from several invocations -- and
    // an engineering review pointed out that asserting it over a duplicated array proved
    // nothing, because there was only ever one invocation in it. So this is a second run.
    const again = auditFile(rustc, file).sites.filter((site) => site.kind === 'usage');
    assert.equal(again.length, 2, 'the second run reported a different number of uses');
    assert.equal(
      new Set([...uses, ...again].map(siteKey)).size,
      2,
      'the same site from two runs did not fold into one',
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

/// Every expansion of a macro is its own use.
///
/// **One `unsafe` block, three uses.** A use inside a `macro_rules!` body is reported once
/// per expansion, and every one of those diagnostics points its primary span at the macro's
/// body -- same file, same byte offset. So the offset that fixed the one-line defect folded
/// three expansions into one site: a security review measured a fourth native call added
/// through a one-line macro inside an already-approved function changing no count at all.
/// The compiler is asked here, because the claim is about what it reports.
test('each expansion of a macro that uses unsafe is its own site', () => {
  const rustc = resolveRustc();
  const base = mkdtempSync(join(tmpdir(), 'fhd-unsafe-macro-'));
  try {
    const file = join(base, 'expanded.rs');
    writeFileSync(
      file,
      [
        '#![deny(unsafe_code)]',
        'macro_rules! native {',
        `    () => {{ ${unsafeBody} }};`,
        '}',
        '#[allow(unsafe_code)]',
        'pub fn three() -> u32 { native!() + native!() + native!() }',
        '',
      ].join('\n'),
      'utf8',
    );
    const { sites, reasons } = auditFile(rustc, file);
    assert.deepEqual(reasons, [], 'the sample must compile, or it proves nothing');
    const uses = sites.filter((site) => site.kind === 'usage');
    assert.equal(uses.length, 3, `the compiler reported ${uses.length} use(s): ${JSON.stringify(uses)}`);
    // The premise: they all point at the one place the `unsafe` is written.
    assert.equal(new Set(uses.map((use) => use.offset)).size, 1, 'the premise failed: the offsets differ');
    assert.equal(new Set(uses.map(siteKey)).size, 3, 'the three expansions share a key');
    // And a use written where it stands still folds with itself.
    const again = auditFile(rustc, file).sites.filter((site) => site.kind === 'usage');
    assert.equal(new Set([...uses, ...again].map(siteKey)).size, 3, 'the same sites did not fold');
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

/// Two invocations in two files, at the same offset in each, are two uses.
///
/// **An offset means nothing without the file it is an offset into.** The first fix keyed a
/// macro's expansions by the call site's byte offset alone -- and every diagnostic for a
/// macro names the *macro's* file as its primary span, so the call site was the only thing
/// separating them. Two invocations that happen to sit at the same offset in two different
/// files therefore folded into one use. A review named it; the two modules here are
/// byte-identical, so the collision is real rather than imagined.
test('the same offset in two different files is two sites', () => {
  const rustc = resolveRustc();
  const base = mkdtempSync(join(tmpdir(), 'fhd-unsafe-collide-'));
  try {
    const file = join(base, 'lib.rs');
    writeFileSync(
      file,
      [
        '#![deny(unsafe_code)]',
        'macro_rules! native {',
        `    () => {{ ${unsafeBody} }};`,
        '}',
        'mod a;',
        'mod b;',
        '',
      ].join('\n'),
      'utf8',
    );
    // The same bytes in both, so the invocation sits at the same offset in each -- and the
    // two files are `a/mod.rs` and `b/mod.rs`, so they share a *basename* too. An
    // engineering review measured that a hop carrying only the basename passed the first
    // version of this test; with this layout, only the path tells them apart.
    const module = ['#[allow(unsafe_code)]', 'pub fn one() -> u32 { native!() }', ''].join('\n');
    mkdirSync(join(base, 'a'));
    mkdirSync(join(base, 'b'));
    writeFileSync(join(base, 'a', 'mod.rs'), module, 'utf8');
    writeFileSync(join(base, 'b', 'mod.rs'), module, 'utf8');

    const { sites, reasons } = auditFile(rustc, file);
    assert.deepEqual(reasons, [], 'the sample must compile, or it proves nothing');
    const uses = sites.filter((site) => site.kind === 'usage');
    assert.equal(uses.length, 2, `the compiler reported ${uses.length} use(s): ${JSON.stringify(uses)}`);
    // The premise, in three parts: one primary span for both, and one offset for both call
    // sites, in two different files.
    assert.equal(new Set(uses.map((use) => `${use.file}:${use.offset}`)).size, 1, 'the premise failed: the primaries differ');
    // A Windows path has a colon of its own, so the split is at the last one. The premise
    // is asserted on the offsets only; whether the *files* are distinguished is the claim
    // under test, so it belongs in the key assertion below and not in the premise -- a
    // first version asserted it here, and a regression then failed as a broken setup
    // rather than as the gate folding two uses.
    const hops = uses.map((use) => use.expansion);
    const at = (hop) => hop.slice(hop.lastIndexOf(':') + 1);
    assert.equal(new Set(hops.map(at)).size, 1, `the premise failed: the offsets differ (${hops})`);
    // And the gate's own key keeps them apart -- which it can only do by the path, since
    // the offset, the primary span and the basename are all shared.
    assert.equal(new Set(uses.map(siteKey)).size, 2, `the two uses share a key (${hops})`);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

/// A target that would not compile has not been audited, and says so.
test('an error the gate cannot classify is reported rather than ignored', () => {
  const rustc = resolveRustc();
  const base = mkdtempSync(join(tmpdir(), 'fhd-unsafe-broken-'));
  try {
    const file = join(base, 'broken.rs');
    writeFileSync(file, 'pub fn f() -> u32 { "not a number" }\n', 'utf8');
    const { reasons } = auditFile(rustc, file);
    assert.ok(reasons.length >= 1, 'a file that does not compile was reported as audited');
    assert.ok(reasons.some((reason) => /mismatched types/u.test(reason)), JSON.stringify(reasons));
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

/// The parser reads both shapes and nothing else.
test('diagnostics are read from rustc and from cargo, and nothing else is', () => {
  const bare = JSON.stringify({
    code: { code: 'E0453' },
    spans: [{
      is_primary: true, file_name: 'crates\\a\\src\\lib.rs', line_start: 7, column_start: 5,
      byte_start: 120, text: [{ text: '    #[allow(unsafe_code)]' }],
    }],
  });
  const wrapped = JSON.stringify({
    reason: 'compiler-message',
    message: {
      code: { code: 'unsafe_code' },
      spans: [{
        is_primary: true, file_name: 'crates/a/src/lib.rs', line_start: 9, column_start: 9,
        byte_start: 210, text: [{ text: 'unsafe { }' }],
      }],
    },
  });
  const noise = ['not json', JSON.stringify({ reason: 'compiler-artifact' }), ''].join('\n');
  const sites = sitesFrom([bare, wrapped, noise].join('\n'));
  assert.deepEqual(sites, [
    {
      kind: 'allowance', file: 'crates/a/src/lib.rs', line: 7, column: 5, offset: 120,
      expansion: null, text: '#[allow(unsafe_code)]',
    },
    {
      kind: 'usage', file: 'crates/a/src/lib.rs', line: 9, column: 9, offset: 210,
      expansion: null, text: 'unsafe { }',
    },
  ]);
  // A span with no offset still yields a site, keyed by line and column instead -- and
  // `unaudited` reports it, so the fallback key never decides a count on its own.
  const spare = JSON.stringify({
    code: { code: 'unsafe_code' },
    spans: [{ is_primary: true, file_name: 'a.rs', line_start: 1, text: [{ text: 'unsafe { }' }] }],
  });
  assert.deepEqual(sitesFrom(spare), [
    { kind: 'usage', file: 'a.rs', line: 1, column: 0, offset: null, expansion: null, text: 'unsafe { }' },
  ]);
  // A span that came from a macro carries the call site it was expanded at.
  const expanded = JSON.stringify({
    code: { code: 'unsafe_code' },
    spans: [{
      is_primary: true,
      file_name: 'a.rs',
      line_start: 2,
      column_start: 14,
      byte_start: 50,
      text: [{ text: 'unsafe { }' }],
      expansion: { span: { file_name: 'caller.rs', byte_start: 300 } },
    }],
  });
  assert.equal(sitesFrom(expanded)[0].expansion, 'caller.rs:300');

  // The two the gate reads are not "unaudited"; anything else at error level is.
  assert.deepEqual(unaudited([bare, wrapped].join('\n')), []);
  const broken = JSON.stringify({ level: 'error', message: 'mismatched types', code: { code: 'E0308' } });
  assert.deepEqual(unaudited(broken), ['mismatched types']);
  // rustc's closing summary is not a reason on its own.
  const summary = JSON.stringify({ level: 'error', message: 'aborting due to 2 previous errors' });
  assert.deepEqual(unaudited(summary), []);
});

/// The comparison, without a compiler: what is approved, for which platform.
test('an allowance is approved per platform, and a missing one is reported', () => {
  const file = 'crates/adapters/platform/src/lib.rs';
  const approved = new Map([[file, {
    allowances: [
      { item: 'fn windows_only() {', platforms: ['win32'] },
      { item: 'fn mac_only() {', platforms: ['darwin'] },
    ],
    uses: { win32: 0, linux: 0, darwin: 0 },
  }]]);
  const site = (line) => ({ kind: 'allowance', file, line, text: '#[allow(unsafe_code)]' });
  const name = (_, line) => (line === 1 ? 'fn windows_only() {' : 'fn mac_only() {');

  // On Windows the Windows one is expected and the macOS one is not compiled.
  assert.deepEqual(findings({ sites: [site(1)], approved, platform: 'win32', name }), []);
  // The same allowance on a platform it is not approved for is a finding.
  const wrong = findings({ sites: [site(1)], approved, platform: 'darwin', name });
  assert.equal(wrong.length, 2, JSON.stringify(wrong));
  assert.match(wrong[0], /not approved for darwin/u);
  assert.match(wrong[1], /not present on darwin: fn mac_only/u);

  // An approved entry the compiler did not report is a finding: the list is a
  // description of the tree, not a wish.
  const absent = findings({ sites: [], approved, platform: 'win32', name });
  assert.equal(absent.length, 1, JSON.stringify(absent));
  assert.match(absent[0], /not present on win32: fn windows_only/u);

  // A module-wide allowance is never approved, whatever item it sits above.
  const inner = findings({
    sites: [{ kind: 'allowance', file, line: 1, text: '#![allow(unsafe_code)]' }],
    approved, platform: 'win32', name,
  });
  assert.match(inner[0], /crate- or module-wide/u);

  // A platform with no count recorded at all is a finding rather than a pass.
  const silent = findings({ sites: [], approved, platform: 'freebsd', name });
  assert.ok(silent.some((one) => /no use count is recorded for freebsd/u.test(one)), JSON.stringify(silent));
});

/// Uses of unsafe in a crate that declares no restriction: the ratchet.
///
/// **No attribute-based scan could see these.** A crate with no `deny(unsafe_code)`
/// needs no allowance to use `unsafe`, so there is no attribute to find -- which is how
/// four uses in two crates sat outside the architecture rule, unreported, for as long
/// as the rule has existed. The compiler reports every one.
test('a use of unsafe that no allowance had to be added for is still counted', () => {
  const file = 'crates/adapters/platform/src/lib.rs';
  const approved = new Map([[file, {
    allowances: [{ item: 'fn one() {', platforms: ['win32'] }],
    uses: { win32: 2, linux: 0, darwin: 0 },
  }]]);
  const name = () => 'fn one() {';
  const allow = { kind: 'allowance', file, line: 1, text: '#[allow(unsafe_code)]' };
  const use = (line) => ({ kind: 'usage', file, line, text: 'unsafe { }' });

  // Exactly what is recorded.
  assert.deepEqual(
    findings({ sites: [allow, use(3), use(4)], approved, platform: 'win32', name }),
    [],
  );

  // **One more, under the same allowance.** This is the hole the count exists to close:
  // an allowance covers a whole item, so a new block inside an approved function needs
  // no new attribute and the first version of this gate skipped it outright.
  const grown = findings({
    sites: [allow, use(3), use(4), use(5)], approved, platform: 'win32', name,
  });
  assert.equal(grown.length, 1, JSON.stringify(grown));
  assert.match(grown[0], /3 use\(s\) of unsafe on win32, and 2 recorded/u);

  // One fewer: the list has gone stale and says so, so it stays a description.
  const shrunk = findings({ sites: [allow, use(3)], approved, platform: 'win32', name });
  assert.match(shrunk[0], /1 use\(s\) of unsafe on win32, and 2 recorded/u);

  // And a use in a file that approves nothing at all.
  const elsewhere = findings({
    sites: [{ kind: 'usage', file: 'crates/other/src/lib.rs', line: 3, text: 'unsafe { }' }],
    approved, platform: 'win32', name,
  });
  assert.match(elsewhere[0], /approves none/u);
});

/// A non-zero exit with nothing to explain it is a target that was not audited.
///
/// **CI found this the hard way.** The gate looked for cargo only under `.tools/`, which
/// CI does not have, so every invocation failed to launch -- and the first version read
/// a quiet failure as "nothing found". Both halves are asserted here: the exit status is
/// part of the answer, and cargo is looked for where it actually is.
test('a run that did not audit anything is not read as a clean one', () => {
  // Exit zero with no diagnostics: audited, and there was nothing to say.
  assert.deepEqual(auditFailed({ status: 0, sites: [], reasons: [], output: '' }), []);
  // Non-zero with the diagnostics this gate reads: that is what a finding looks like.
  assert.deepEqual(
    auditFailed({ status: 1, sites: [{ kind: 'usage' }], reasons: [], output: '' }),
    [],
  );
  // Non-zero with nothing at all: not audited.
  const quiet = auditFailed({ status: 101, sites: [], reasons: [], output: '' });
  assert.equal(quiet.length, 1, JSON.stringify(quiet));
  assert.match(quiet[0], /exited 101 with no diagnostic this gate can read/u);
  // And it says what cargo said, without the command line cargo echoes.
  const noisy = auditFailed({
    status: 101,
    sites: [],
    reasons: [],
    output: ['error: no such option', 'Caused by:', `  rustc ${'x'.repeat(4000)}`].join('\n'),
  });
  assert.match(noisy[0], /error: no such option/u);
  assert.ok(noisy[0].length < 400, `the reason is ${noisy[0].length} characters long`);
  // A reason the compiler itself gave is carried through untouched.
  assert.deepEqual(
    auditFailed({ status: 1, sites: [], reasons: ['mismatched types'], output: '' }),
    ['mismatched types'],
  );

  // **A process that did not finish did not audit anything**, whatever it printed first.
  // One diagnostic used to be enough to call a target audited, so a run killed part-way
  // through, or one that failed for something cargo prints as plain text, passed on the
  // strength of the lines it managed to emit. A security review named it.
  const killed = auditFailed({
    status: null, signal: 'SIGKILL', sites: [{ kind: 'usage' }], reasons: [], output: '',
  });
  assert.equal(killed.length, 1, JSON.stringify(killed));
  assert.match(killed[0], /killed by SIGKILL part-way through/u);

  // No status at all, which is what a spawn that never completed leaves.
  assert.match(
    auditFailed({ status: null, sites: [{ kind: 'usage' }], reasons: [], output: '' })[0],
    /did not report an exit status/u,
  );

  // A failure cargo reports as plain text, after our diagnostics have been read.
  const other = auditFailed({
    status: 101,
    signal: null,
    sites: [{ kind: 'usage' }],
    reasons: [],
    output: [
      JSON.stringify({ code: { code: 'unsafe_code' }, level: 'error', message: 'usage of an unsafe block' }),
      'error: linker `cc` not found',
      'error: could not compile `queue-secrets` (lib test) due to 1 previous error',
    ].join('\n'),
  });
  assert.equal(other.length, 1, JSON.stringify(other));
  assert.match(other[0], /for a reason this gate does not recognise/u);
  assert.match(other[0], /linker/u);

  // And the ordinary case stays ordinary: the forbid fired, cargo said it could not
  // compile, and that is the whole story.
  assert.deepEqual(
    auditFailed({
      status: 101,
      signal: null,
      sites: [{ kind: 'usage' }],
      reasons: [],
      output: [
        JSON.stringify({ code: { code: 'unsafe_code' }, level: 'error', message: 'usage of an unsafe block' }),
        'error: could not compile `fhd-platform` (lib) due to 52 previous errors',
      ].join('\n'),
    }),
    [],
  );
});

/// The two shapes that still read as audited, both measured by an engineering review.
///
/// **Neither of these is cargo dying.** The completion check above fires when the process
/// this gate started is killed and the OS says so -- and that covers neither of the ways a
/// run can stop having looked at everything:
///
///   * rustc crashes and cargo exits *normally*, reporting the crash on an indented
///     `Caused by:` line and writing `could not compile X (lib)` with no `due to` tail;
///   * cargo is killed on Windows, which has no signal delivery, so it exits 1 with
///     `signal: null` -- the same event that is reported on Linux was audited here.
///
/// The first is told apart by the tail the forbid case always writes; the second by cargo's
/// own `build-finished` marker, which `--message-format=json` emits on success and failure
/// alike. Both were measured against the real toolchain before they were relied on.
test('a run that stopped before it was done is not audited', () => {
  const crash = [
    JSON.stringify({ reason: 'compiler-message', message: { code: { code: 'unsafe_code' }, level: 'error' } }),
    JSON.stringify({ reason: 'build-finished', success: false }),
    'error: could not compile `fhd-platform` (lib)',
    '',
    'Caused by:',
    "  process didn't exit successfully: `rustc ...` (exit code: 0xc0000005, STATUS_ACCESS_VIOLATION)",
  ].join('\n');
  const crashed = auditFailed({
    status: 101, signal: null, sites: [{ kind: 'usage' }], reasons: [], output: crash,
    expectFinished: true,
  });
  assert.equal(crashed.length, 1, JSON.stringify(crashed));
  assert.match(crashed[0], /for a reason this gate does not recognise/u);
  // And the reason names the crash rather than the first three lines that begin with a
  // matching word -- which, measured, were three `warning:` lines.
  assert.match(crashed[0], /STATUS_ACCESS_VIOLATION/u);

  // And the tail is load-bearing on its own. The shape above is caught twice over -- by
  // the `Caused by:` lines as well -- so here is a run that says only that it could not
  // compile, with no count of errors behind it: that is not the forbid firing, and a
  // mutation that exempts every `could not compile` line has to fail on this.
  const untold = auditFailed({
    status: 101,
    signal: null,
    sites: [{ kind: 'usage' }],
    reasons: [],
    output: [
      JSON.stringify({ reason: 'build-finished', success: false }),
      'error: could not compile `fhd-platform` (lib)',
    ].join('\n'),
    expectFinished: true,
  });
  assert.equal(untold.length, 1, JSON.stringify(untold));
  assert.match(untold[0], /for a reason this gate does not recognise/u);

  // Killed on Windows: an exit code, no signal, and no marker.
  const killed = auditFailed({
    status: 1, signal: null, sites: [{ kind: 'usage' }], reasons: [], output: '',
    expectFinished: true,
  });
  assert.equal(killed.length, 1, JSON.stringify(killed));
  assert.match(killed[0], /stopped before cargo reported the build finished/u);

  // The ordinary forbid-fired run carries the marker and the tail, and stays clean.
  assert.deepEqual(
    auditFailed({
      status: 101,
      signal: null,
      sites: [{ kind: 'usage' }],
      reasons: [],
      output: [
        JSON.stringify({ reason: 'build-finished', success: false }),
        'error: could not compile `queue-secrets` (lib) due to 7 previous errors',
      ].join('\n'),
      expectFinished: true,
    }),
    [],
  );

  // And the marker is asked of cargo only: `auditFile` drives rustc, which emits none.
  assert.deepEqual(
    auditFailed({
      status: 101,
      signal: null,
      sites: [{ kind: 'usage' }],
      reasons: [],
      output: 'error: aborting due to 1 previous error',
    }),
    [],
  );
});

/// A diagnostic with no byte offset is reported, not keyed around.
///
/// rustc 1.98 always carries one, so this is a stream shape it does not produce -- and that
/// is the point: the fallback key is the file and line, which is exactly what folded two
/// uses on one line into one. An engineering review named the gap. It fails rather than
/// counts.
test('a site with no byte offset is reported as unaudited', () => {
  const reasons = unaudited(JSON.stringify({
    code: { code: 'unsafe_code' },
    level: 'error',
    spans: [{ is_primary: true, file_name: 'crates/a/src/lib.rs', line_start: 3 }],
  }));
  assert.equal(reasons.length, 1, JSON.stringify(reasons));
  assert.match(reasons[0], /carries no byte offset/u);
  // With an offset, it is an ordinary site and no reason at all.
  assert.deepEqual(
    unaudited(JSON.stringify({
      code: { code: 'unsafe_code' },
      level: 'error',
      spans: [{ is_primary: true, file_name: 'a.rs', line_start: 3, byte_start: 40 }],
    })),
    [],
  );
});

/// An expansion this gate cannot identify is reported, not folded.
///
/// **The same defect as the collision above, one layer out.** The chain of call sites is
/// what separates two invocations of a macro, since every diagnostic for one names the
/// macro's own file as its primary span. So a hop missing its file or its offset, and a
/// chain longer than the walk follows, both leave two uses sharing a key -- and a security
/// review measured that happening at sixteen levels of nesting with nothing reported,
/// because the check that existed looked only at the primary span. rustc 1.98 emits both
/// halves and nothing here nests that deep; this is a ratchet on shapes it does not
/// produce, which is the standard already applied to the primary span.
test('an expansion the gate cannot identify is reported as unaudited', () => {
  const site = (expansion) => JSON.stringify({
    code: { code: 'unsafe_code' },
    level: 'error',
    spans: [{
      is_primary: true, file_name: 'crates/a/src/lib.rs', line_start: 3, byte_start: 40, expansion,
    }],
  });
  // An ordinary call site, fully identified: nothing to report.
  assert.deepEqual(unaudited(site({ span: { file_name: 'crates/a/src/use.rs', byte_start: 9 } })), []);

  // A hop with no offset, and a hop with no file: each one leaves two uses sharing a key.
  const noOffset = unaudited(site({ span: { file_name: 'crates/a/src/use.rs' } }));
  assert.equal(noOffset.length, 1, JSON.stringify(noOffset));
  assert.match(noOffset[0], /carries no file or no byte offset/u);
  const noFile = unaudited(site({ span: { byte_start: 9 } }));
  assert.equal(noFile.length, 1, JSON.stringify(noFile));
  assert.match(noFile[0], /carries no file or no byte offset/u);

  // And a chain longer than the gate follows, built from the inside out.
  let deep = { span: { file_name: 'crates/a/src/use.rs', byte_start: 1 } };
  for (let level = 0; level < EXPANSION_LIMIT + 1; level += 1) {
    deep = { span: { file_name: 'crates/a/src/use.rs', byte_start: level + 2, expansion: deep } };
  }
  const truncated = unaudited(site(deep));
  assert.equal(truncated.length, 1, JSON.stringify(truncated));
  assert.match(truncated[0], /expanded through more than 16 macros/u);
  // One hop short of the limit is still identified, so the ratchet has a defined edge.
  let shallow = { span: { file_name: 'crates/a/src/use.rs', byte_start: 1 } };
  for (let level = 0; level < EXPANSION_LIMIT - 2; level += 1) {
    shallow = { span: { file_name: 'crates/a/src/use.rs', byte_start: level + 2, expansion: shallow } };
  }
  assert.deepEqual(unaudited(site(shallow)), []);
});

/// The two ratchets on what the compiler cannot report, and what this gate does not run.
///
/// `exportedMacros` exists because `unsafe_code` is declared without
/// `report_in_external_macro`: a use arriving from a macro defined in another crate is
/// reported by nobody. A security review measured three raw pointer reads in a crate that
/// denies `unsafe`, with zero diagnostics from either crate. No crate here exports a macro,
/// and this keeps it so -- by one literal, failing on any occurrence, because deciding what
/// an occurrence *means* by reading text is the mistake this gate was written to stop.
///
/// `unauditableTargets` exists because a build script runs at build time with the machine's
/// authority and a proc-macro runs inside the compiler, and both were skipped in silence.
test('what the compiler cannot report, and what the gate does not run, fail closed', () => {
  assert.deepEqual(
    exportedMacros('D:/repo', () => ['D:/repo/crates/a/src/lib.rs'], () => 'pub fn plain() {}'),
    [],
  );
  const found = exportedMacros(
    'D:/repo',
    () => ['D:/repo/crates/a/src/lib.rs'],
    () => '#[macro_export]\nmacro_rules! native { () => { unsafe { } } }',
  );
  assert.equal(found.length, 1, JSON.stringify(found));
  assert.match(found[0], /crates\/a\/src\/lib\.rs mentions macro_export/u);
  // The workspace as it stands exports none, which is what the ratchet holds.
  assert.deepEqual(exportedMacros(), []);

  assert.deepEqual(unauditableTargets({ packages: [{ name: 'p', targets: [{ kind: ['lib'], name: 'p' }] }] }), []);
  const kinds = unauditableTargets({
    packages: [{
      name: 'p',
      targets: [
        { kind: ['custom-build'], name: 'build-script-build' },
        { kind: ['proc-macro'], name: 'p-macros' },
        { kind: ['lib'], name: 'p' },
      ],
    }],
  });
  assert.equal(kinds.length, 2, JSON.stringify(kinds));
  assert.match(kinds[0], /custom-build target/u);
  assert.match(kinds[1], /proc-macro target/u);
});

/// Cargo is looked for where the project keeps it, and then where everyone else does.
test('cargo is found without the project-local toolchain', () => {
  assert.equal(resolveCargo('D:/nowhere', () => false), 'cargo');
  const local = resolveCargo('D:/nowhere', () => true);
  assert.match(local, /[\\/]\.tools[\\/]cargo[\\/]bin[\\/]cargo/u);
});

/// One invocation per target, because `cargo rustc` refuses extra arguments otherwise.
test('every buildable target is selected, one at a time, and again as its harness', () => {
  const targets = targetsFrom({
    packages: [
      {
        name: 'a',
        targets: [
          { kind: ['lib'], name: 'a', test: true },
          { kind: ['test'], name: 'smoke', test: true },
        ],
      },
      {
        name: 'b',
        targets: [
          { kind: ['bin'], name: 'tool', test: false },
          { kind: ['custom-build'], name: 'build-script-build', test: false },
        ],
      },
    ],
  });
  assert.deepEqual(targets.map((one) => [one.package, ...one.flags]), [
    ['a', '--lib'],
    // **The lib again as its own test harness**, which is a different configuration of
    // the same file: `--lib` alone compiles without `cfg(test)`, so an `unsafe` block
    // inside a `#[cfg(test)]` module is invisible to it. A security review named the
    // hole.
    ['a', '--lib', '--profile', 'test'],
    // A `test` target is a harness already: cargo passes `--test` for it, and asking
    // again is an error.
    ['a', '--test', 'smoke'],
    ['b', '--bin', 'tool'],
  ]);
});

/// A signature is read as one line however the file wraps it.
///
/// **This is why the gate broke, and why the fix is here rather than in the entry.**
/// An allowance used to be pinned to the first line below the attribute, so an entry
/// could only name a signature rustfmt had left on one line. Adding a return type to
/// `link_into_directory` pushed it across five lines, the entry stopped matching, and
/// CI failed at the gate on two platforms over a change that had nothing to do with
/// `unsafe`. The other half of the same weakness was already recorded: a wrapped
/// signature could only be approved by its bare `fn name(`, which left a parameter
/// free to change from `&File` to `&Path` -- the one regression the publication
/// contract exists to forbid -- with the allowance still satisfied.
test('an item is read as one line however its signature is wrapped', () => {
  const wrapped = [
    '    #[allow(unsafe_code)]',
    '    pub fn link_into_directory(',
    '        file: &File,',
    '        directory: &File,',
    '        name: &OsStr,',
    '    ) -> Result<(), LinkFailure> {',
  ];
  assert.equal(
    itemBelow(wrapped, 0),
    'pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> Result<(), LinkFailure> {',
  );

  // The same signature on one line reads identically, which is the point: an entry
  // says the same thing whichever way the file is formatted.
  assert.equal(
    itemBelow(
      [
        '    #[allow(unsafe_code)]',
        '    pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> Result<(), LinkFailure> {',
      ],
      0,
    ),
    itemBelow(wrapped, 0),
  );

  // Comments, blank lines and further attributes are still walked over, and the head
  // stops at the brace rather than running into the body.
  assert.equal(
    itemBelow(
      [
        '#[allow(unsafe_code)]',
        '// why this one is sound',
        '',
        '#[cfg(target_os = "linux")]',
        'pub fn our_uid() -> u32 {',
        '    let value = 0;',
      ],
      0,
    ),
    'pub fn our_uid() -> u32 {',
  );

  // A declaration that ends in a semicolon is a head too.
  assert.equal(
    itemBelow(['#[allow(unsafe_code)]', 'extern "C" {', '    fn geteuid() -> u32;'], 0),
    'extern "C" {',
  );

  // And a parameter that changed is a different item, which is the property the
  // strengthened entry rests on.
  assert.notEqual(
    itemBelow(
      [
        '    #[allow(unsafe_code)]',
        '    pub fn move_into_directory(',
        '        from: &File,',
        '        from_name: &OsStr,',
        '        to: &Path,',
        '        to_name: &OsStr,',
        '    ) -> io::Result<()> {',
      ],
      0,
    ),
    'pub fn move_into_directory(from: &File, from_name: &OsStr, to: &File, to_name: &OsStr) -> io::Result<()> {',
  );
});

/// The lists this gate is read against say what they are.
test('the approved list is shaped as the gate reads it, and complete for every platform', () => {
  const platforms = ['win32', 'linux', 'darwin'];
  for (const [file, entry] of APPROVED) {
    assert.match(file, /^crates\//u);
    assert.ok(entry.allowances.length > 0, `${file}: approves nothing`);
    for (const one of entry.allowances) {
      assert.ok(one.item.length > 0, `${file}: an entry with no item`);
      assert.ok(one.platforms.length > 0, `${file}: ${one.item} is approved nowhere`);
      for (const platform of one.platforms) {
        assert.ok(
          platforms.includes(platform),
          `${file}: ${one.item} names a platform this project does not build: ${platform}`,
        );
      }
    }
    // **A count for every platform, including zero.** A platform left out would read as
    // "nothing recorded", and the gate reports that rather than passing -- but the list
    // should not be putting it in that position in the first place.
    for (const platform of platforms) {
      assert.equal(
        typeof entry.uses[platform],
        'number',
        `${file}: no use count for ${platform}`,
      );
      assert.ok(entry.uses[platform] >= 0, `${file}: a negative count for ${platform}`);
    }
    // Every platform that approves something should have something to approve.
    for (const platform of platforms) {
      const approves = entry.allowances.some((one) => one.platforms.includes(platform));
      if (!approves) {
        assert.equal(
          entry.uses[platform],
          0,
          `${file}: ${entry.uses[platform]} use(s) recorded on ${platform} with no ` +
          'allowance approved there, which cannot both be true',
        );
      }
    }
  }
});
