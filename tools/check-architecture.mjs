import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Package names, not Cargo dependency aliases. Every workspace member is classified.
const layers = {
  // Temporary pure-rule migration bridge; remove when resume rules move into domain.
  'fhd-domain': ['resume-policy'],
  'fhd-app': ['fhd-domain', 'fhd-config'],
  'fhd-runtime': ['fhd-app', 'fhd-domain', 'fhd-config', 'fhd-telemetry'],
  'fhd-http': ['fhd-app', 'fhd-domain', 'fhd-config', 'fhd-telemetry'],
  'fhd-storage': ['fhd-app', 'fhd-domain', 'fhd-config', 'fhd-telemetry'],
  'fhd-persistence': ['fhd-app', 'fhd-domain', 'fhd-config', 'fhd-telemetry'],
  'fhd-secrets': ['fhd-app', 'fhd-domain', 'fhd-config', 'fhd-telemetry'],
  'fhd-platform': ['fhd-app', 'fhd-domain', 'fhd-config', 'fhd-telemetry'],
  'fhd-policy': ['fhd-app', 'fhd-domain', 'fhd-config', 'fhd-telemetry'],
  'fhd-protocol': ['fhd-domain'],
  // fhd-platform is the one crate §4 allows unsafe, and it exposes operating
  // system primitives rather than a port's implementation: the control surface
  // cannot express §3.1's pipe security without it.
  'fhd-ipc': ['fhd-app', 'fhd-protocol', 'fhd-config', 'fhd-telemetry', 'fhd-platform'],
  'fhd-telemetry': [],
  'fhd-config': ['fhd-domain'],
  'fhd-testkit': ['fhd-app', 'fhd-domain', 'fhd-config'],
  'fhd': ['fhd-protocol', 'fhd-config', 'fhd-telemetry'],
  'fhd-native-host': ['fhd-protocol', 'fhd-config', 'fhd-telemetry'],
  'fhd-daemon': [
    'fhd-app', 'fhd-domain', 'fhd-runtime', 'fhd-http', 'fhd-storage',
    'fhd-persistence', 'fhd-secrets', 'fhd-platform', 'fhd-policy',
    'fhd-protocol', 'fhd-ipc', 'fhd-telemetry', 'fhd-config',
  ],
};

// Transitional exceptions are exact existing edges, not a wildcard for old crates.
const legacy = {
  'download-core': [],
  'resume-policy': [],
  'transfer-store': [],
  'queue-secrets': [],
  'platform-files': [],
  'download-engine': [
    'download-core', 'resume-policy', 'transfer-store', 'queue-secrets', 'platform-files',
  ],
};
const pureDependencies = new Set(['serde', 'thiserror']);

// The workflow names the packages it tests, one step per area, so a failure on a
// runner whose logs we cannot read still says where it is. The cost of naming
// them is that a new member could ship untested; this is that cost paid.
// Every place in the tree allowed to write `unsafe`: which file, and which item.
//
// The policy used to be a comment beside the dependency rules, which is close
// to not having one. Counting the attributes was the next version and was still
// too weak: moving an allowance to another item, or widening it from a function
// to the module around it, keeps the count identical. So an approved allowance
// names the item it sits on, and an inner `#![allow(unsafe_code)]` -- which
// covers everything below it -- is never approved.
//
// Widening this is an edit to this file, which is reviewed. It is a gate, not
// the review: an approved entry still needs somebody to have agreed that the
// call in it is sound.
export const UNSAFE_ALLOWANCES = new Map([
  ['crates/adapters/platform/src/lib.rs', [
    // `our_uid` calls `geteuid(2)`: no arguments, no pointers, cannot fail.
    'fn our_uid() -> u32 {',
    // `link_into_directory`, twice: there are two of it, one per platform, and
    // an entry approves one allowance. Naming both is the point of this list
    // being a description of the tree rather than a count.
    //
    // Windows calls `NtSetInformationFile` with `FILE_LINK_INFORMATION`; Linux
    // calls `linkat(2)` through the descriptor's entry under `/proc/self/fd`.
    // Both take borrowed descriptors and a name owned by the caller for longer
    // than the call, and both are the only route on their system from an open
    // handle to a new name without resolving a path -- which is the property
    // the whole publication design rests on.
    'pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {',
    'pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {',
    // `clone_into_directory` calls `fclonefileat(2)` on macOS. Same shape as the
    // linkers -- borrowed descriptors, a name owned here, a status back -- and
    // measured rather than adopted: nothing in the engine calls it, and the
    // publication contract says what adopting it would require first.
    'pub fn clone_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {',
    // `open_in_directory` calls `openat(2)` and `move_into_directory` calls
    // `renameatx_np`, the second and third steps of the candidate macOS path.
    // Both take borrowed descriptors and names owned by the caller, and both
    // are measured rather than adopted: nothing in the engine calls them.
    'pub fn open_in_directory(directory: &File, name: &OsStr) -> io::Result<File> {',
    // This one is a bare `pub fn move_into_directory(` because `itemBelow`
    // returns a single trimmed line and the signature is wrapped across several.
    // So it is the weakest entry here: changing a parameter -- `to: &Path`
    // instead of `to: &File`, which is exactly the regression the publication
    // contract forbids -- keeps the allowance satisfied. An engineering review
    // pointed that out. Pinning it would mean teaching `itemBelow` to read a
    // whole signature, and the entry is left as it is with the limit written
    // down rather than papered over: the parameters are also asserted by
    // `crates/adapters/platform/tests/publication_macos.rs`, which would stop
    // compiling if they changed.
    'pub fn move_into_directory(',
  ]],
]);

// The item an attribute sits on: the next line that is not blank, a comment, or
// another attribute.
function itemBelow(lines, from) {
  for (let index = from + 1; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line || line.startsWith('//') || line.startsWith('#[') || line.startsWith('#![')) continue;
    return line;
  }
  return '<end of file>';
}

/// `text` with Rust comments removed, leaving string literals alone.
///
/// F1 in the re-review of 11dd794: `#[allow /* reason */ (unsafe_code)]` is
/// valid Rust, silences the lint, and walked past a gate that stripped only
/// whitespace before looking for `allow(`. Block comments nest in Rust, line
/// comments run to the newline, and a `/*` inside a string is not a comment --
/// all three matter, because getting any of them wrong leaves a gate that can
/// be talked past with punctuation.
export function withoutComments(text) {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const two = text.slice(i, i + 2);
    if (two === '/*') {
      let depth = 0;
      while (i < text.length) {
        const here = text.slice(i, i + 2);
        if (here === '/*') { depth += 1; i += 2; continue; }
        if (here === '*/') { depth -= 1; i += 2; if (depth === 0) break; continue; }
        i += 1;
      }
      out += ' ';
      continue;
    }
    if (two === '//') {
      while (i < text.length && text[i] !== '\n') i += 1;
      out += ' ';
      continue;
    }
    // Raw strings: r"..." and r#.."..".."#, where the hash count sets the end.
    if (text[i] === 'r' && (text[i + 1] === '"' || text[i + 1] === '#')) {
      let j = i + 1;
      let hashes = 0;
      while (text[j] === '#') { hashes += 1; j += 1; }
      if (text[j] === '"') {
        const close = `"${'#'.repeat(hashes)}`;
        const end = text.indexOf(close, j + 1);
        const stop = end === -1 ? text.length : end + close.length;
        out += text.slice(i, stop);
        i = stop;
        continue;
      }
    }
    if (text[i] === '"') {
      out += text[i];
      i += 1;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\') { out += text.slice(i, i + 2); i += 2; continue; }
        out += text[i];
        i += 1;
      }
      out += text[i] ?? '';
      i += 1;
      continue;
    }
    out += text[i];
    i += 1;
  }
  return out;
}

/// Every attribute in `text`, as whole attributes rather than lines.
///
/// A line-based scan was the flaw the review of 2026-09-24 found: it matched
/// the prefix `#[allow(unsafe_code)]` and nothing else, so `#[allow(dead_code,
/// unsafe_code)]`, `#[cfg_attr(unix, allow(unsafe_code))]` and any attribute
/// split across lines went straight past a gate that claimed to bound them.
///
/// Brackets are matched so a nested attribute comes back whole. String literals
/// inside an attribute are skipped so a `]` in a doc string or a `cfg` value
/// does not end it early. This is not a Rust parser, which is why the caller
/// refuses every spelling it does not recognise instead of interpreting it.
export function attributesIn(text) {
  const found = [];
  for (let i = 0; i + 1 < text.length; i += 1) {
    if (text[i] !== '#') continue;
    let open = i + 1;
    const inner = text[open] === '!';
    if (inner) open += 1;
    if (text[open] !== '[') continue;
    let depth = 0;
    let end = -1;
    for (let j = open; j < text.length; j += 1) {
      const ch = text[j];
      // Comments are skipped here, not later. Stripping them afterwards was
      // too late: `#[allow /* ] */ (unsafe_code)]` ended at the bracket inside
      // the comment, so the attribute came back as `#[allow /* ]`, which does
      // not mention unsafe_code and was dropped without ever being examined.
      // Rust nests block comments, so the depth is counted.
      if (text.slice(j, j + 2) === '/*') {
        let comment = 0;
        while (j < text.length) {
          const here = text.slice(j, j + 2);
          if (here === '/*') { comment += 1; j += 2; continue; }
          if (here === '*/') { comment -= 1; j += 2; if (comment === 0) break; continue; }
          j += 1;
        }
        j -= 1;
        continue;
      }
      if (text.slice(j, j + 2) === '//') {
        while (j < text.length && text[j] !== '\n') j += 1;
        continue;
      }
      if (ch === '"') {
        j += 1;
        while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
        continue;
      }
      if (ch === '[') depth += 1;
      else if (ch === ']') {
        depth -= 1;
        if (depth === 0) { end = j; break; }
      }
    }
    // An attribute that never closes is malformed; the compiler will say so.
    if (end === -1) continue;
    found.push({
      text: text.slice(i, end + 1),
      inner,
      line: text.slice(0, i).split('\n').length,
      after: end + 1,
    });
    i = end;
  }
  return found;
}

/// Whether an attribute's text would permit unsafe code somewhere.
///
/// `allow` and `expect` both silence `deny(unsafe_code)`; `expect` was missed
/// entirely before. `deny` and `forbid` mentions are the policy itself and are
/// left alone -- but only when the attribute does not *also* allow, so
/// `cfg_attr(windows, allow(unsafe_code))` beside a deny is still caught.
function permitsUnsafe(text) {
  const bare = withoutComments(text);
  if (!bare.includes('unsafe_code')) return false;
  const stripped = bare.replaceAll(/\s+/gu, '');
  return stripped.includes('allow(') || stripped.includes('expect(');
}

export function checkUnsafePolicy(root) {
  const offenders = [];
  // Which approved items were actually found, so the list can be checked
  // against the tree once every file has been read.
  const seen = new Map();
  walkSources(`${root}/crates`, (full) => {
    if (!full.endsWith('.rs')) return;
    const relative = full.slice(root.length + 1).split('\\').join('/');
    const text = readFileSync(full, 'utf8');
    offenders.push(...unsafeOffendersIn(relative, text));
    seen.set(relative, allowedItemsIn(text));
  });
  offenders.push(...unusedAllowances(seen));
  return offenders;
}

/// The items an approved-spelling allowance sits on in this text.
function allowedItemsIn(text) {
  const lines = text.split("\n").map(line => line.replace(/\r$/u, ""));
  const items = [];
  for (const attribute of attributesIn(text)) {
    if (!permitsUnsafe(attribute.text) || attribute.inner) continue;
    if (withoutComments(attribute.text).replaceAll(/\s+/gu, '') !== '#[allow(unsafe_code)]') continue;
    items.push(itemBelow(lines, attribute.line - 1));
  }
  return items;
}

/// Source files git would treat as binary, so no diff of them is ever reviewed.
///
/// A raw NUL byte in a `.rs` file makes git call it binary: `git show` prints
/// `Bin 54933 -> 56189 bytes` and **no diff at all**, and ripgrep skips the file
/// entirely. One such byte sat in the composition root, written as a literal NUL
/// inside a byte-string literal instead of `\x00`. Both independent reviews of
/// this branch found it, from opposite directions: the engineering review because
/// grep could not search the file, the security review because the commit's
/// changes to the replacement policy -- the very subject of the review -- were
/// invisible in the diff. It is the cheapest way to get a change past this
/// project, so the gate refuses it.
///
/// `\x00` in an escape is the same byte to rustc and keeps the file text.
///
/// The first version of this check walked `crates` and looked only at `.rs`.
/// Both re-reviews made the same point about that: the hiding place is not the
/// Rust code, it is any tracked text file. A NUL in a migration's `.sql` hides a
/// changed `CHECK` constraint, one in a workflow hides a changed CI step, and
/// one in this file hides the gate's own rules. So the scan covers the source
/// trees that make up the product and the extensions that carry logic.
///
/// A third review widened it again, and its examples are better than the rule
/// was. `Cargo.lock` and `rust-toolchain.toml` are where hiding a change would
/// pay best -- a dependency or a pinned toolchain nobody reviewed -- and both sat
/// outside the scan. `docs/` was outside it too, which is where the mojibake
/// damage actually happened, and where the Arabic product documentation lives.
/// And `tools/rust.ps1` was exempt from the rule named after PowerShell strings:
/// `.ps1` was not in this list at all.
///
/// `''` in `TREES` is the repository root, which picks up the root manifest,
/// `Cargo.lock`, `rust-toolchain.toml`, `package.json`, `README.md` and
/// `AGENTS.md` without descending anywhere new -- `walkSources` recurses, so the
/// root entry covers every tree; the named ones stay for the error messages and
/// for the test that each is reached.
export const REVIEWABLE = [
  '.rs', '.sql', '.mjs', '.js', '.ts', '.toml', '.yml', '.yaml', '.md', '.ps1', '.lock', '.json',
];
export const TREES = ['', 'crates', 'tools', '.github', 'docs'];
export function checkReviewableSources(root, trees = TREES) {
  const offenders = [];
  const seen = new Set();
  const judge = (full) => {
    if (seen.has(full)) return;
    seen.add(full);
    const bytes = readFileSync(full);
    const relative = full.slice(root.length + 1).split('\\').join('/');
    const at = bytes.indexOf(0);
    if (at !== -1) {
      offenders.push(
        `${relative}: a raw NUL byte at offset ${at} makes git diff this file as ` +
        `binary, so no change to it is ever reviewed. Write it as the escape \\x00.`,
      );
    }
    offenders.push(...shellEscapeWreckage(relative, bytes));
    offenders.push(...doubleEncodedText(relative, bytes));
  };
  for (const tree of trees) {
    const base = tree ? `${root}/${tree}` : root;
    if (!existsSync(base)) continue;
    // The root is scanned without descending. Recursing from it would walk
    // `.tools/`, where this project keeps its pinned Rust toolchain -- thousands
    // of files it does not own and does not track. The named trees below are
    // where recursion belongs.
    if (!tree) {
      for (const entry of readdirSync(base)) {
        if (!REVIEWABLE.some((extension) => entry.endsWith(extension))) continue;
        const full = `${base}/${entry}`;
        let stat;
        try { stat = statSync(full); } catch { continue; }
        if (stat.isDirectory()) continue;
        judge(full);
      }
      continue;
    }
    walkSources(base, judge);
  }
  return offenders;
}

/// What a PowerShell string edit leaves behind when its escapes are not what the
/// author thought they were.
///
/// This machine is Windows, and editing a source by building a string in
/// PowerShell has now damaged files three separate times: a BOM plus mojibake'd
/// Arabic, a raw NUL that made a whole reviewed diff invisible, and -- twice in
/// one file -- backtick escapes. Backtick-r became a carriage return, which Node
/// treats as a line terminator: it ended a `//` comment mid-sentence and the
/// rest of the line became code, so the gate itself stopped parsing.
/// Backtick-n went the other way and stayed literal, sitting inside a comment
/// where a line break was meant, where it compiled and shipped and was found
/// only by reading.
///
/// The escapes are named in words here on purpose: spelled as one-letter code
/// spans they are the pattern below, and this file is scanned by it.
///
/// Two byte-level signatures, both with no legitimate spelling in this tree:
///
///   * a CR that is not part of a CRLF, or a U+2028/U+2029 in a JavaScript
///     source -- all three end a line for a JavaScript parser, and none is
///     written on purpose here;
///   * a backtick followed by one of PowerShell's escape letters, with **no
///     closing backtick before the end of that line**.
///
/// The second signature started out as "followed by whitespace", which two
/// reviews took apart from both sides at once. It rejected ordinary prose --
/// `` `0 stopped in Completed` `` in a permissions document, and the very
/// paragraph in `docs/development.md` that documents this rule, since a literal
/// backtick has no other Markdown spelling. And it missed the commoner shape of
/// the damage: the instance that shipped was caught only because the next line
/// happened to be indented, so a literal escape before a full stop or a quote
/// went through. Asking whether the span *closes on its line* answers both:
/// `` `n` `` and `` `nothing here` `` close, a stray escape does not.
///
/// The letters are all of PowerShell's, not the four that happened to bite us.
/// A literal backtick-e produces a raw ESC, as invisible in a review as the NUL
/// the sibling rule exists for.
///
/// It reads bytes, not text, so a file this rule would reject cannot hide behind
/// being undecodable.
export function shellEscapeWreckage(relative, bytes) {
  const offenders = [];
  const ESCAPES = new Set([...'0abefnrtv'].map((letter) => letter.charCodeAt(0)));
  const javascript = ['.mjs', '.js', '.ts'].some((extension) => relative.endsWith(extension));
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] === 0x0d && bytes[index + 1] !== 0x0a) {
      offenders.push(
        `${relative}: a carriage return at offset ${index} with no newline after it. ` +
        'A parser and git both end the line there, so whatever follows on the ' +
        "line is read as code. It is PowerShell's ``r`` escape; edit the file " +
        'with an editor instead of building its text in a shell string.',
      );
    }
    // U+2028 and U+2029. A JavaScript parser ends a line on these exactly as it
    // does on the CR above, so a `//` comment holding one has the same defect.
    if (javascript && bytes[index] === 0xe2 && bytes[index + 1] === 0x80 &&
        (bytes[index + 2] === 0xa8 || bytes[index + 2] === 0xa9)) {
      offenders.push(
        `${relative}: a U+202${bytes[index + 2] === 0xa8 ? '8' : '9'} at offset ${index}. ` +
        'JavaScript ends a line there, so a comment holding one stops being a ' +
        'comment partway through. Nothing here writes one on purpose.',
      );
    }
    if (bytes[index] !== 0x60 || !ESCAPES.has(bytes[index + 1])) continue;
    // Not the tail of a run of backticks. A Markdown fence with a language tag
    // -- ```text, ```rust, ```bash, ```none -- puts an escape letter directly
    // after a backtick, and there is no closing backtick on that line. Widening
    // the rule to unclosed spans turned every fenced block in `docs/` into an
    // offender, which is how this exception got measured rather than guessed.
    if (bytes[index - 1] === 0x60) continue;
    // Does the span close before the line does?
    let closed = false;
    for (let scan = index + 2; scan < bytes.length; scan += 1) {
      if (bytes[scan] === 0x0a || bytes[scan] === 0x0d) break;
      if (bytes[scan] === 0x60) { closed = true; break; }
    }
    if (!closed) {
      offenders.push(
        `${relative}: \`${String.fromCharCode(bytes[index + 1])} at offset ${index}, ` +
        'and no closing backtick before the end of the line. That is a ' +
        "PowerShell escape left literal, not a code span -- a character that " +
        'never became what it was meant to be. Write the text with an editor.',
      );
    }
  }
  return offenders;
}

/// Text that has been decoded once too many times.
///
/// The first of the three PowerShell damages was this: `Get-Content -Raw |
/// Set-Content` read UTF-8 as the system codepage and wrote it back, so `§`
/// became two characters and Arabic became runs of Latin-1 punctuation. It
/// compiled, the tests passed, and `docs/development.md` wrote the hazard down --
/// while **eight occurrences stayed in the tree**, five of them in the first four
/// lines of the crate under review, until a security review counted them. A
/// documented hazard that nothing checks is a hazard.
///
/// The signature is one of three specific characters immediately followed by a
/// `C2`-prefixed one. `§` is `C2 A7`, and read as Latin-1 and re-encoded it
/// becomes `C3 82 C2 A7`; Arabic letters are `D8`/`D9` pairs and become
/// `C3 98 C2 xx` or `C3 99 C2 xx`. So the leads are `C3 82`, `C3 98` and
/// `C3 99` -- the re-encodings of the lead bytes this repository's real text
/// actually uses.
///
/// It started as "any `C3` character before any `C2` one", which a run over
/// `docs/` refuted: `docs/status-report-2026-09-23.md` contains `C3 97 C2 BB`,
/// which is the multiplication sign in "15x" followed by a closing Arabic quote
/// -- ordinary text. Adjacent Latin-1 supplement characters are legal, so the
/// rule has to name the leads rather than the range. That narrows it: mojibake
/// through some other lead byte would pass, which is the honest limit of a
/// byte-pattern check and is written down in `docs/development.md`.
///
/// The examples are given as hex on purpose. Written out they are the pattern,
/// and this file is scanned by it -- the same reason the escapes above are named
/// in words.
export function doubleEncodedText(relative, bytes) {
  const offenders = [];
  const LEADS = new Set([0x82, 0x98, 0x99]);
  for (let index = 0; index < bytes.length - 2; index += 1) {
    if (bytes[index] !== 0xc3) continue;
    if (!LEADS.has(bytes[index + 1])) continue;
    if (bytes[index + 2] !== 0xc2) continue;
    offenders.push(
      `${relative}: text decoded twice at offset ${index} -- a C3 character ` +
      'directly before a C2 one, which is what UTF-8 read as a system codepage ' +
      'and written back looks like. Restore the file and edit it with an editor.',
    );
  }
  return offenders;
}

/// Walks a tree, handing each reviewable file to `visit`.
///
/// Shared rather than copied: this traversal existed twice, verbatim, and the
/// second copy is how the NUL check came to cover a narrower tree than the
/// comment above it claimed. A dangling symlink is skipped rather than allowed
/// to throw, which would fail the gate with an error about nothing.
export function walkSources(directory, visit) {
  for (const entry of readdirSync(directory)) {
    if (entry === 'target' || entry === '.git' || entry === 'node_modules') continue;
    const full = `${directory}/${entry}`;
    let stat;
    try { stat = statSync(full); } catch { continue; }
    if (stat.isDirectory()) { walkSources(full, visit); continue; }
    if (!REVIEWABLE.some((extension) => entry.endsWith(extension))) continue;
    visit(full);
  }
}

/// The policy itself, over one file's text. Exported so it can be tested on
/// spellings that do not exist in the tree.
export function unsafeOffendersIn(relative, text) {
  const offenders = [];
  const approved = UNSAFE_ALLOWANCES.get(relative) ?? [];
  const remaining = [...approved];
  const lines = text.split("\n").map(line => line.replace(/\r$/u, ""));
  for (const attribute of attributesIn(text)) {
    if (!permitsUnsafe(attribute.text)) continue;
    const where = `${relative}:${attribute.line}`;
    if (attribute.inner) {
      offenders.push(
        `${where}: a crate- or module-wide unsafe allowance is never approved. ` +
        'Attach it to the one item that needs it.',
      );
      continue;
    }
    // One spelling is approved, and everything else is refused rather than
    // interpreted. A gate that guesses at what an attribute means is a gate
    // whose coverage nobody can state.
    if (withoutComments(attribute.text).replaceAll(/\s+/gu, '') !== '#[allow(unsafe_code)]') {
      offenders.push(
        `${where}: unsafe is permitted by a spelling this gate does not accept: ` +
        `${attribute.text.replaceAll(/\s+/gu, ' ')}. Write it as #[allow(unsafe_code)] ` +
        'on the single item that needs it, so the allowance has one reviewable form.',
      );
      continue;
    }
    const item = itemBelow(lines, attribute.line - 1);
    const at = remaining.indexOf(item);
    if (at === -1) {
      offenders.push(
        `${where}: unsafe allowed on an item that is not approved: ${item}. ` +
        'Add it to UNSAFE_ALLOWANCES in this file, which is reviewed, or remove it.',
      );
      continue;
    }
    remaining.splice(at, 1);
  }
  return offenders;
}

/// Approved allowances that no longer exist in the tree.
///
/// This used to live inside `unsafeOffendersIn`, which is a predicate over one
/// file's *text* -- so it answered "this approved item is missing" for every
/// synthetic source a test handed it, and the tests only passed while the list
/// happened to hold a single entry that they happened to include. Whether the
/// list still describes the tree is a question about the tree, so it is asked
/// where the tree is read.
export function unusedAllowances(seen) {
  const offenders = [];
  for (const [relative, approved] of UNSAFE_ALLOWANCES) {
    const remaining = [...approved];
    for (const item of seen.get(relative) ?? []) {
      const at = remaining.indexOf(item);
      if (at !== -1) remaining.splice(at, 1);
    }
    for (const unused of remaining) {
      offenders.push(
        `${relative}: approved unsafe allowance is no longer present: ${unused}. ` +
        'Remove it from UNSAFE_ALLOWANCES so the list stays a description of the tree.',
      );
    }
  }
  return offenders;
}

export function checkTestCoverage(metadata, workflow) {
  const members = metadata.workspace_members
    .map(id => metadata.packages.find(pkg => pkg.id === id))
    .filter(Boolean)
    .map(pkg => pkg.name);
  const named = new Set();
  for (const line of workflow.split('\n')) {
    if (!/cargo \+[\d.]+ test /.test(line)) continue;
    for (const part of line.split(/\s+/)) {
      if (part.startsWith('-') || part === 'test' || part === 'run:') continue;
      named.add(part);
    }
  }
  return members.filter(name => !named.has(name))
    .map(name => `${name}: no test step in the workflow names this package`);
}

export function checkArchitecture(metadata) {
  if (!metadata || !Array.isArray(metadata.packages) ||
      !Array.isArray(metadata.workspace_members) || metadata.workspace_members.length === 0) {
    throw new Error('Expected nonempty cargo metadata packages and workspace_members');
  }
  const packagesById = new Map(metadata.packages.map(pkg => [pkg.id, pkg]));
  const members = metadata.workspace_members.map(id => {
    const pkg = packagesById.get(id);
    if (!pkg || typeof pkg.name !== 'string' || !Array.isArray(pkg.dependencies)) {
      throw new Error('Workspace member missing from metadata or has invalid dependencies');
    }
    return pkg;
  });
  const workspaceNames = new Set(members.map(pkg => pkg.name));
  if (workspaceNames.size !== members.length) throw new Error('Duplicate workspace package names');
  const violations = [];
  for (const pkg of members) {
    const allowed = Object.hasOwn(layers, pkg.name) ? layers[pkg.name] :
      Object.hasOwn(legacy, pkg.name) ? legacy[pkg.name] : undefined;
    if (!allowed) {
      violations.push(`${pkg.name}: unclassified workspace package`);
      continue;
    }
    for (const dep of pkg.dependencies) {
      if (typeof dep.name !== 'string' || ![null, undefined, 'normal', 'dev', 'build'].includes(dep.kind)) {
        throw new Error(`Invalid dependency metadata in ${pkg.name}`);
      }
      const kind = dep.kind ?? 'normal';
      const detail = `${kind}${dep.target ? `, target=${dep.target}` : ''}${dep.rename ? `, alias=${dep.rename}` : ''}`;
      const edge = `${pkg.name} -> ${dep.name} (${detail})`;
      const internal = workspaceNames.has(dep.name) || Object.hasOwn(layers, dep.name) ||
        Object.hasOwn(legacy, dep.name) || dep.name.startsWith('fhd-');
      if (internal) {
        // Domain tests remain pure; testkit depends on app and must never invert that edge.
        const testkit = kind === 'dev' && dep.name === 'fhd-testkit' &&
          Object.hasOwn(layers, pkg.name) && !['fhd-domain', 'fhd-testkit'].includes(pkg.name);
        if (!allowed.includes(dep.name) && !testkit) violations.push(`${edge}: forbidden layer dependency`);
      } else if (['fhd-domain', 'download-core', 'resume-policy'].includes(pkg.name)) {
        // An allowlist also catches unknown I/O libraries and aliases, unlike a tokio/reqwest denylist.
        if (kind === 'build' || (!pureDependencies.has(dep.name) && !(kind === 'dev' && dep.name === 'proptest'))) {
          violations.push(`${edge}: external dependency not approved for pure domain`);
        }
      }
    }
  }
  return violations;
}

function main(args) {
  let json;
  if (args.length === 2 && args[0] === '--metadata') {
    // Windows PowerShell may write a UTF-8 BOM; accept it without changing JSON semantics.
    json = readFileSync(args[1], 'utf8').replace(/^\uFEFF/u, '');
  } else if (args.length === 0) {
    const result = spawnSync('cargo', ['metadata', '--no-deps', '--format-version=1', '--locked', '--offline'], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, shell: false,
    });
    if (result.error) throw result.error;
    if (result.status !== 0) throw new Error(`cargo metadata failed (${result.status}): ${result.stderr.trim()}`);
    json = result.stdout;
  } else {
    throw new Error('Usage: node tools/check-architecture.mjs [--metadata cargo-metadata.json]');
  }
  const metadata = JSON.parse(json);
  const violations = checkArchitecture(metadata);
  if (violations.length) throw new Error(`Architecture violations:\n${violations.join('\n')}`);
  // A member that no test step names would ship green and untested.
  const workflow = readFileSync(fileURLToPath(new URL('../.github/workflows/engine.yml', import.meta.url)), 'utf8');
  const untested = checkTestCoverage(metadata, workflow);
  if (untested.length) throw new Error(`Untested workspace members:\n${untested.join('\n')}`);
  // An unsafe allowance that nobody approved would otherwise be one attribute
  // away from being policy.
  const root = fileURLToPath(new URL('..', import.meta.url)).replace(/[\\/]$/u, '');
  const unapproved = checkUnsafePolicy(root);
  if (unapproved.length) throw new Error(`Unapproved unsafe allowances:\n${unapproved.join('\n')}`);
  // A source file git diffs as binary cannot be reviewed at all, which is worse
  // than any single rule this gate enforces on what the file says.
  const unreviewable = checkReviewableSources(root);
  if (unreviewable.length) throw new Error(`Sources no diff would show:\n${unreviewable.join('\n')}`);
  // Says what was scanned, not "every source". A review pointed out that the
  // previous wording claimed more than the walk covers, which is the same kind
  // of overclaim this gate exists to make expensive.
  console.log(`Architecture dependency rules passed (${metadata.workspace_members.length} workspace packages, each named by a test step, unsafe allowances as approved, no NUL bytes, stray shell escapes or twice-decoded text in ${TREES.map((tree) => tree || '<root>').join('/')} sources).`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
