import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  APPROVED, auditFailed, auditFile, findings, itemBelow, resolveCargo, sitesFrom, targetsFrom,
  unaudited,
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
    spans: [{ is_primary: true, file_name: 'crates\\a\\src\\lib.rs', line_start: 7, text: [{ text: '    #[allow(unsafe_code)]' }] }],
  });
  const wrapped = JSON.stringify({
    reason: 'compiler-message',
    message: {
      code: { code: 'unsafe_code' },
      spans: [{ is_primary: true, file_name: 'crates/a/src/lib.rs', line_start: 9, text: [{ text: 'unsafe { }' }] }],
    },
  });
  const noise = ['not json', JSON.stringify({ reason: 'compiler-artifact' }), ''].join('\n');
  const sites = sitesFrom([bare, wrapped, noise].join('\n'));
  assert.deepEqual(sites, [
    { kind: 'allowance', file: 'crates/a/src/lib.rs', line: 7, text: '#[allow(unsafe_code)]' },
    { kind: 'usage', file: 'crates/a/src/lib.rs', line: 9, text: 'unsafe { }' },
  ]);

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
