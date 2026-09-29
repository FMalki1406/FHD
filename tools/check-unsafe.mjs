// Where `unsafe` is permitted, enumerated by the compiler rather than by reading text.
//
// **Why this replaces a scanner.** The gate used to find allowance attributes with a
// hand-written lexer, and four rounds of review found four ways past it: an item on the
// attribute's own line, whitespace between `#` and `[`, a raw string holding a quote and
// a `]`, a string spanning two lines, and a raw string with more hashes than the scan
// looked at. Every one was the same mistake -- reading text where the compiler reads
// tokens -- and every fix was one more special case. So the scanner is gone.
//
// What replaces it is the compiler's own answer. Compiled with `-F unsafe_code`, a
// command-line forbid that no attribute can override, rustc reports:
//
//   * `E0453` for every attribute that tries to permit unsafe -- `allow`, `expect`,
//     `cfg_attr(..., allow(...))`, inner or outer, however it is spelled or spaced,
//     with the file and line it sits on;
//   * the `unsafe_code` lint for every use of `unsafe` it analyses -- with one exception
//     the compiler itself makes, named below.
//
// Nothing here parses Rust. What it does is compare two sets: the allowances the
// compiler found, and the allowances this file approves.
//
// **The exception, because it is a real hole and it is the compiler's own.** The
// `unsafe_code` lint is declared without `report_in_external_macro`, so rustc does not
// report a use that comes from a macro defined in *another* crate -- and that is a lint
// property, not an attribute, so the command-line forbid does not override it. A security
// review measured it: a `macro_rules!` exported from a crate with no restriction, holding
// a raw pointer read, expanded three times in a crate that denies `unsafe`, produced zero
// diagnostics from both crates. A macro's body is not analysed where it is defined either,
// so there is no invocation of the compiler that reports it.
//
// What closes it is not more compiling but a smaller claim plus a ratchet: no crate in
// this workspace exports a macro, and `exportedMacros` fails the gate if one appears. The
// check is deliberately a search for one literal, so anything that even mentions it fails
// closed and has to be decided by a person. Same-crate macros are reported normally, and
// each expansion is its own site -- see `siteKey`.
//
// **What it covers, exactly.** The configurations the compiler compiles. An allowance
// behind `#[cfg(target_os = "freebsd")]` is invisible on the platforms this project
// builds -- and that is the whole claim: the gate covers what the supported targets
// compile, and each CI job covers its own platform. The scanner it replaces read every
// `cfg` branch, which is the one thing lost; it also mis-read five of them, which is
// what was gained.
//
// **And it sees something the scanner never could**: `unsafe` in a crate that declares
// no restriction at all. Such code needs no allowance attribute, so an attribute-based
// scan cannot see it. Here every use is reported, and a use in a file this list does
// not name is a finding.
import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

/// Where `unsafe` is permitted, and how much of it, per platform.
///
/// **Two numbers per file, and both are pinned.** `allowances` is the items an
/// allowance may sit on; `uses` is how many `unsafe` blocks the compiler should find
/// there. The second exists because the first is not enough: an allowance covers a whole
/// item, so a new `unsafe` block added inside an already-approved function needs no new
/// attribute and would otherwise pass unseen. A security review found exactly that hole
/// in the first version of this gate, which skipped every use in a file that approved
/// anything.
///
/// **The platforms are part of the entry**, because the compiler answers for one
/// configuration at a time: there is one linker implementation per system, three unwired
/// macOS primitives, and two free-space implementations. An entry absent on Windows may
/// be perfectly present on macOS, and each CI job checks its own platform's numbers.
///
/// Widening any of this is an edit to this file, which is reviewed. It is a gate, not
/// the review: an approved entry still needs somebody to have agreed that the call in it
/// is sound.
export const APPROVED = new Map([
  ['crates/adapters/platform/src/lib.rs', {
    allowances: [
      // `our_uid` calls `geteuid(2)`: no arguments, no pointers, cannot fail.
      { item: 'fn our_uid() -> u32 {', platforms: ['linux', 'darwin'] },
      // Windows calls `NtSetInformationFile` with `FILE_LINK_INFORMATION`; Linux calls
      // `linkat(2)` through the descriptor's entry under `/proc/self/fd`. Both take
      // borrowed descriptors and a name owned by the caller for longer than the call, and
      // both are the only route on their system from an open handle to a new name without
      // resolving a path -- which is the property the whole publication design rests on.
      // The return type is part of the entry: it carries whether the mechanism issued its
      // call, which is the only thing publication may read as "no name was created".
      {
        item: 'pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> Result<(), LinkFailure> {',
        platforms: ['win32', 'linux'],
      },
      // `clone_into_directory` calls `fclonefileat(2)`, `open_in_directory` calls
      // `openat(2)`, and `move_into_directory` calls `renameatx_np`: the three steps of
      // the candidate macOS path. All take borrowed descriptors and names owned here, and
      // all are measured rather than adopted -- nothing in the engine calls them, and the
      // publication contract says what adopting them would require first.
      {
        item: 'pub fn clone_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {',
        platforms: ['darwin'],
      },
      {
        item: 'pub fn open_in_directory(directory: &File, name: &OsStr) -> io::Result<File> {',
        platforms: ['darwin'],
      },
      {
        item: 'pub fn move_into_directory(from: &File, from_name: &OsStr, to: &File, to_name: &OsStr) -> io::Result<()> {',
        platforms: ['darwin'],
      },
    ],
    // Measured per platform, because `cfg` decides which of these compile: on Windows
    // the named-pipe and link paths, on Linux `linkat` and `geteuid`, on macOS the three
    // clone primitives and `geteuid`.
    uses: { win32: 51, linux: 2, darwin: 5 },
  }],
  // **These two were outside the rule until the compiler said so.** Neither crate
  // declared any restriction, so its native calls needed no allowance to be written and
  // an attribute-based scan could not see them -- four uses, unreported for as long as
  // the rule has existed. Each call has now been read: the free-space queries check their
  // return before using what it wrote, and the DPAPI path bounds every buffer and copies
  // out only after success, a non-null pointer and a length inside its own maximum. The
  // calls stay in their crates, where their contracts are; what was added is a
  // crate-level ban and these named exceptions, so the gate pins them by signature.
  ['crates/platform-files/src/lib.rs', {
    allowances: [
      {
        item: 'pub fn available_space(path: &Path) -> io::Result<u64> {',
        platforms: ['win32', 'linux', 'darwin'],
      },
    ],
    uses: { win32: 1, linux: 2, darwin: 2 },
  }],
  // The wipe in `Output::drop` is bounded by `LocalSize` rather than by the blob's own
  // `cbData`, because it runs on the failure path and while unwinding, where nothing has
  // checked that field -- see the note on the function. The wipe itself lives in
  // `wipe_and_release`, which takes the allocator's two calls as parameters: that is what
  // makes the bound measurable, and it is an `unsafe fn` so that taking it is still a
  // decision this gate counts.
  ['crates/queue-secrets/src/lib.rs', {
    allowances: [
      {
        item: 'fn transform(input: &[u8], encrypt: bool) -> Result<Vec<u8>, Error> {',
        platforms: ['win32'],
      },
      {
        item: 'unsafe fn wipe_and_release(block: *mut u8, size: impl FnOnce(*mut u8) -> usize, free: impl FnOnce(*mut u8)) {',
        platforms: ['win32'],
      },
      // **The `unsafe fn` is the point, and it is why there are three entries.** The first
      // version of this seam was a *safe* function taking a raw pointer, a write length and
      // a deallocator -- so a call to it needed no `unsafe`, `#![deny(unsafe_code)]` did not
      // reach it, this gate did not count it, and the signature recorded here ratified a
      // caller-chosen write length. Both reviews arrived at that independently. As an
      // `unsafe fn` every caller is a use the gate counts, including the tests' one wrapper
      // below, which is where their side of the precondition is discharged.
      {
        item: 'fn wipe(block: *mut u8, size: impl FnOnce(*mut u8) -> usize, free: impl FnOnce(*mut u8)) {',
        platforms: ['win32'],
      },
    ],
    // Nothing outside `cfg(windows)`, so no other platform compiles a single one. Six on
    // win32: the two crypt calls counted once at their `unsafe` block, the copy out of the
    // blob, the declaration of the `unsafe fn`, the wipe inside it, the call to it from
    // `Output::drop`, and the tests' wrapper.
    uses: { win32: 6, linux: 0, darwin: 0 },
  }],
]);

/// The chain of call sites a diagnostic was expanded through, innermost first.
///
/// `null` for code written where it stands, which is nearly all of it. A span whose
/// expansion carries no byte offset contributes `unknown`, which folds -- deliberately:
/// `unaudited` reports a span with no offset, so a count is never quietly taken from one.
/// The walk is bounded because the chain is data from a process, not a promise.
export function expansionOf(span, limit = 16) {
  const through = [];
  let hop = span?.expansion;
  while (hop && through.length < limit) {
    const at = hop.span?.byte_start;
    through.push(typeof at === 'number' ? at : 'unknown');
    hop = hop.span?.expansion;
  }
  return through.length ? through.join('<') : null;
}

/// The diagnostics that matter, from a stream of rustc or cargo JSON lines.
///
/// Both shapes are accepted: rustc writes a diagnostic per line, cargo wraps it under
/// `reason: compiler-message`. Anything else on the stream is ignored, except an error
/// this gate cannot classify -- see `unaudited`.
export function sitesFrom(output) {
  const sites = [];
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const diagnostic = parsed.reason === 'compiler-message' ? parsed.message : parsed;
    if (!diagnostic || typeof diagnostic !== 'object') continue;
    const code = diagnostic.code?.code;
    if (code !== 'E0453' && code !== 'unsafe_code') continue;
    const primary = (diagnostic.spans ?? []).find((span) => span.is_primary);
    if (!primary) continue;
    sites.push({
      kind: code === 'E0453' ? 'allowance' : 'usage',
      file: primary.file_name.replaceAll('\\', '/'),
      line: primary.line_start,
      // **The column and the byte offset, because a line is not a site.** Two `unsafe`
      // blocks can sit on one line, and the compiler reports each of them -- but a key
      // made of the file and the line alone folded them into one, so a file with two
      // uses on a line counted one and a new block added beside an existing one changed
      // no number. A security review proved it with the two diagnostics. The byte offset
      // is what identifies a site; the column is kept for a reader and for the rare
      // diagnostic that carries no offset.
      column: primary.column_start ?? 0,
      offset: primary.byte_start ?? null,
      // **Where it was expanded, when it came out of a macro.** A use inside a
      // `macro_rules!` body is reported once per expansion, and every one of those
      // diagnostics points its primary span at the macro's body -- the same file and the
      // same byte offset. So the offset alone folded three expansions into one site, and a
      // fourth native call added through a one-line macro inside an already-approved
      // function would have changed no count at all. A security review measured that end
      // to end through `findings`. The call site chain is part of what makes a site here.
      expansion: expansionOf(primary),
      text: (primary.text?.[0]?.text ?? '').trim(),
    });
  }
  return sites;
}

/// What makes one site one site, for folding the same one reported by several targets.
///
/// **The byte offset, not the line.** Two `unsafe` blocks can sit on one line, and a key
/// made of the file and the line folded them into one: a file with two uses on a line
/// counted one, and a block added beside an existing one changed no number -- in the very
/// count that exists to make adding one a decision somebody agrees to. A security review
/// proved it with the two diagnostics rustc emits. The line and column are what a reader
/// needs; the offset is what identifies the site, with the line and column as the key for
/// the rare span that carries no offset -- and such a span is reported by `unaudited`, so
/// no count is taken from a stream that contains one.
///
/// **And where it was expanded, if it was.** Every expansion of a same-crate macro points
/// its primary span at the macro's body, so the offset alone made three uses one site.
/// The call site chain separates them.
export function siteKey(site) {
  const where = site.offset ?? `${site.line}:${site.column}`;
  const from = site.expansion ? `@${site.expansion}` : '';
  return `${site.kind}:${site.file}:${where}${from}`;
}

/// Errors that are neither of the two this gate reads, which mean the enumeration for
/// that target is incomplete.
///
/// **A target that would not compile has not been audited**, and a gate that cannot
/// say so is a gate that goes quiet exactly when something is wrong. So these are
/// reported rather than ignored.
export function unaudited(output) {
  const reasons = [];
  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const diagnostic = parsed.reason === 'compiler-message' ? parsed.message : parsed;
    if (!diagnostic || diagnostic.level !== 'error') continue;
    const code = diagnostic.code?.code;
    if (code === 'E0453' || code === 'unsafe_code') {
      // **A site with no byte offset is not a site this gate can count.** The key falls
      // back to the line and column, and two uses on one line whose spans carry neither
      // fold into one -- which is the defect this round was about, one step further out.
      // rustc 1.98 always reports both, so this is unreachable through it; it is here so
      // that a stream where it is missing fails rather than counts. An engineering review
      // named the gap.
      const primary = (diagnostic.spans ?? []).find((span) => span.is_primary);
      if (primary && typeof primary.byte_start !== 'number') {
        reasons.push(
          `a ${code === 'E0453' ? 'E0453' : 'use-of-unsafe'} diagnostic in ` +
          `${primary.file_name ?? 'an unnamed file'} carries no byte ` +
          'offset, so its site cannot be told apart from another on the same line',
        );
      }
      continue;
    }
    // The summary rustc prints after the real errors, which is not itself a reason.
    if (/^aborting due to/u.test(diagnostic.message ?? '')) continue;
    if (/^For more information/u.test(diagnostic.message ?? '')) continue;
    reasons.push(diagnostic.message ?? 'an error with no message');
  }
  return reasons;
}

/// `text` past any attributes it begins with, for naming an item.
///
/// **Naming, not detection.** This is reached only after the compiler has said an
/// allowance exists on a given line; all it decides is which item to print. So it
/// steps over leading attributes by counting brackets and nothing more -- a comment
/// or a literal holding a bracket would give a worse name, and a worse name in a
/// message is the whole cost. Everything this project used to decide by reading Rust
/// like this is now decided by the compiler.
function pastAttributes(text) {
  let rest = text.replace(/\/\/.*$/u, '').replace(/\r$/u, '').trimStart();
  while (rest.startsWith('#')) {
    const open = rest.indexOf('[');
    if (open === -1) break;
    let depth = 0;
    let index = open;
    for (; index < rest.length; index += 1) {
      if (rest[index] === '[') depth += 1;
      else if (rest[index] === ']') {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    if (index >= rest.length) break;
    rest = rest.slice(index + 1).trimStart();
  }
  return rest.trim();
}

// The item an attribute sits on, **as one line however it is written in the file**:
// the next line that is not blank, a comment, or another attribute, and every line
// after it up to the `{` or `;` that ends the item's head.
//
// **It used to return that first line and nothing else**, and two things followed.
// An entry could only pin a signature that rustfmt had left on one line, so widening
// a parameter from `&File` to `&Path` -- the regression the publication contract
// exists to forbid -- kept a wrapped signature's allowance satisfied. That was
// recorded as a known weakness. And it made the gate brittle in the other direction:
// adding a return type to `link_into_directory` pushed its signature across lines,
// the recorded entry stopped matching, and CI failed at the gate on two platforms for
// a change that had nothing to do with `unsafe`.
//
// So the head is joined and normalised to the form a reader would write it in: one
// space between tokens, no padding just inside the brackets, and no trailing comma
// before the closing one. An entry therefore says the same thing whether the file has
// the signature on one line or five.
export function itemBelow(lines, from, rest = '') {
  const head = [];
  // **What follows the attribute on its own line is part of the item.**
  //
  // This is where an unapproved function used to walk through. The scan began on
  // the *next* line, so `#[allow(unsafe_code)] pub fn whatever() {` had its item
  // read from the line below -- and where that line held an approved signature,
  // the allowance was matched and the function that actually carried it was never
  // examined. An independent review reproduced the pass with no offence reported.
  // Leading attributes on the same line are stepped over the same way they are on
  // lines of their own.
  const sameLine = pastAttributes(rest);
  if (sameLine) {
    head.push(sameLine);
    if (sameLine.endsWith('{') || sameLine.endsWith(';')) {
      return normalizeItem(head.join(' '));
    }
  }
  let index = from + 1;
  for (; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line || line.startsWith('//') || line.startsWith('#[') || line.startsWith('#![')) continue;
    break;
  }
  if (index >= lines.length) return head.length ? normalizeItem(head.join(' ')) : '<end of file>';
  // Twenty lines is far more than any signature in this tree and stops a file
  // without a terminator from being read to its end.
  for (let scan = index; scan < lines.length && scan < index + 20; scan += 1) {
    const line = lines[scan].trim();
    if (line) head.push(line);
    if (line.endsWith('{') || line.endsWith(';')) break;
  }
  return normalizeItem(head.join(' '));
}


/// One line, spaced the way a signature is written rather than the way it is wrapped.
export function normalizeItem(text) {
  return text
    .replace(/\s+/gu, ' ')
    .replace(/\(\s+/gu, '(')
    .replace(/,\s*\)/gu, ')')
    .replace(/\s+\)/gu, ')')
    .trim();
}

/// The item an allowance sits on, read from the file the compiler named.
///
/// **This is naming, not detection.** The compiler decides that an allowance exists and
/// where; this only says which item it is, so a person reading the report knows what to
/// look at and so the approved list can pin a signature. If it misreads, a message is
/// wrong -- it cannot hide an allowance, which is what every earlier defect did.
export function itemAt(file, line, read = (path) => readFileSync(path, 'utf8')) {
  const text = read(resolvePath(root, file));
  const lines = text.split('\n').map((one) => one.replace(/\r$/u, ''));
  const attribute = lines[line - 1] ?? '';
  const closing = attribute.lastIndexOf(']');
  const rest = closing === -1 ? '' : attribute.slice(closing + 1);
  return itemBelow(lines, line - 1, rest);
}

/// Every finding, given what the compiler reported and what this file approves.
export function findings({ sites, approved = APPROVED, platform, name = itemAt }) {
  const messages = [];
  const expected = new Map();
  for (const [file, entry] of approved) {
    const wanted = entry.allowances.filter((one) => one.platforms.includes(platform));
    expected.set(file, wanted.map((one) => one.item));
  }
  const matched = new Map([...expected].map(([file, items]) => [file, [...items]]));
  const uses = new Map();

  for (const site of sites) {
    if (site.kind === 'usage') {
      uses.set(site.file, (uses.get(site.file) ?? 0) + 1);
      if (!approved.has(site.file)) {
        messages.push(
          `${site.file}:${site.line}: unsafe is used in a file that approves none. ` +
          `${site.text}`,
        );
      }
      continue;
    }
    if (site.text.startsWith('#![')) {
      messages.push(
        `${site.file}:${site.line}: a crate- or module-wide unsafe allowance is never ` +
        'approved. Attach it to the one item that needs it.',
      );
      continue;
    }
    const item = name(site.file, site.line);
    const remaining = matched.get(site.file);
    const at = remaining?.indexOf(item) ?? -1;
    if (at === -1) {
      messages.push(
        `${site.file}:${site.line}: unsafe allowed on an item that is not approved ` +
        `for ${platform}: ${item}. Add it to APPROVED in tools/check-unsafe.mjs, ` +
        'which is reviewed, or remove it.',
      );
      continue;
    }
    remaining.splice(at, 1);
  }

  for (const [file, left] of matched) {
    for (const item of left) {
      messages.push(
        `${file}: an approved unsafe allowance is not present on ${platform}: ${item}. ` +
        'Remove it, or correct the platforms it is approved for, so the list stays a ' +
        'description of the tree.',
      );
    }
  }

  // **The count, which is the half an allowance cannot carry.** An allowance covers a
  // whole item, so a new `unsafe` block inside an approved function needs no new
  // attribute; pinning how many the compiler should find is what makes adding one a
  // change somebody has to agree to. A count that has gone down is reported too, so the
  // list stays a description of the tree rather than a ceiling.
  for (const [file, entry] of approved) {
    const recorded = entry.uses[platform];
    if (recorded === undefined) {
      messages.push(
        `${file}: no use count is recorded for ${platform}, so nothing here says how ` +
        'much unsafe this file should have on it.',
      );
      continue;
    }
    const found = uses.get(file) ?? 0;
    if (found !== recorded) {
      messages.push(
        `${file}: ${found} use(s) of unsafe on ${platform}, and ${recorded} recorded. ` +
        'A new one needs a review before the number changes; one that has gone needs ' +
        'the number corrected.',
      );
    }
  }
  return messages;
}

/// Whether a run actually audited what it was given.
///
/// **A non-zero exit with nothing to explain it is a target that was not audited.**
/// Under `-F unsafe_code` a findings-free target exits zero, and a target with findings
/// exits non-zero *with* diagnostics this gate reads. Anything else -- a flag cargo
/// rejected, a lock it could not take, a toolchain that is not installed -- comes back
/// non-zero with no JSON at all, and the first version of this gate read that as
/// "nothing found". A security review named it: the exit status has to be part of the
/// answer, not ignored because the diagnostics were quiet.
export function auditFailed({ status, signal, sites, reasons, output, expectFinished = false }) {
  const said = () => output.split('\n').map((line) => line.trim())
    // cargo echoes the whole rustc command line on failure, thousands of characters of
    // no use to a reader. What is wanted is what it said went wrong.
    .filter((line) => /^(error|warning|Caused by|failed)/u.test(line))
    .map((line) => (line.length > 160 ? `${line.slice(0, 160)}...` : line))
    .slice(0, 3)
    .join(' / ');
  if (reasons.length) return reasons;
  // **A process that did not finish did not audit anything**, whatever it managed to
  // print first. A security review pointed out that one diagnostic was enough to call a
  // target audited, so a run killed part-way through -- or one that failed for a reason
  // cargo prints as plain text, like a linker it could not find -- was read as a clean
  // pass on the strength of the lines it happened to emit before it stopped.
  if (signal) return [`was killed by ${signal} part-way through: ${said() || 'and said nothing'}`];
  if (typeof status !== 'number') return [`did not report an exit status: ${said() || 'and said nothing'}`];
  // **Cargo says when it has finished, and on Windows nothing else does.** An engineering
  // review measured that a cargo killed from outside exits 1 with no signal on win32 --
  // Windows has no signal delivery -- so the check above fires only on POSIX, on the two
  // platforms whose counts this file does not record. `--message-format=json` ends with
  // `build-finished` on success and on failure alike (measured on both), so its absence is
  // the one platform-independent way to see a run that stopped before it was done. This is
  // asked for only of cargo; `auditFile` drives rustc, which emits no such marker.
  if (expectFinished && !/"reason":\s*"build-finished"/u.test(output)) {
    return [`stopped before cargo reported the build finished (exit ${status}): ${said() || 'and said nothing'}`];
  }
  if (status === 0) return [];
  // A non-zero exit is expected when the forbid fires -- and then cargo says only that it
  // could not compile, after the diagnostics this gate has already read. Any other
  // complaint means something else went wrong, and a target that failed for something
  // else was not audited for this.
  //
  // **And "could not compile" is only that story when it names the errors.** When the
  // forbid fires, cargo writes `could not compile X (lib) due to 7 previous errors` -- the
  // tail is always there, measured against the real run. When rustc *crashes*, cargo exits
  // normally and writes `could not compile X (lib)` with no tail, then an indented
  // `Caused by: process didn't exit successfully ... STATUS_ACCESS_VIOLATION`. The old
  // filter exempted every `could not compile` line and read no indented line at all, so a
  // compiler that died after one diagnostic was reported as audited. An engineering review
  // measured it; requiring the tail is what tells the two apart.
  const unexplained = output.split('\n').map((line) => line.trim())
    .filter((line) => !line.startsWith('{'))
    .filter((line) => /^(error(:|\[)|Caused by:|process didn't exit successfully)/u.test(line))
    .filter((line) => !/^error: could not compile .* due to \d+ previous error/u.test(line))
    .filter((line) => !/^error: aborting due to /u.test(line));
  if (unexplained.length) {
    // What a reader needs is the line that says what went wrong, not the first three lines
    // that begin with a word this filter matches -- which, an engineering review measured,
    // were three `warning:` lines while the linker error scrolled past.
    const named = unexplained.map((line) => (line.length > 160 ? `${line.slice(0, 160)}...` : line))
      .slice(0, 3).join(' / ');
    return [`exited ${status} for a reason this gate does not recognise: ${named || said()}`];
  }
  if (sites.length) return [];
  return [`exited ${status} with no diagnostic this gate can read: ${said() || 'and said nothing'}`];
}

/// Compiles one file with the forbid and returns what the compiler said.
export function auditFile(rustc, path, extra = []) {
  const run = spawnSync(
    rustc,
    ['--crate-type', 'lib', '--edition', '2021', '--emit=metadata', '-F', 'unsafe_code',
      '--error-format=json', '-o', `${path}.meta`, ...extra, path],
    { encoding: 'utf8' },
  );
  if (run.error) return { sites: [], reasons: [`could not run ${rustc}: ${run.error.message}`] };
  const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;
  const sites = sitesFrom(output);
  const reasons = unaudited(output);
  return {
    sites,
    reasons: auditFailed({ status: run.status, signal: run.signal, sites, reasons, output }),
  };
}

/// The workspace's Rust sources, for the one check the compiler cannot make.
function sources(from, found = []) {
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    const path = `${from}/${entry.name}`;
    if (entry.isDirectory()) {
      if (entry.name === 'target' || entry.name === '.git') continue;
      sources(path, found);
    } else if (entry.name.endsWith('.rs')) {
      found.push(path);
    }
  }
  return found;
}

/// A ratchet on the one hole the compiler leaves: a macro exported to another crate.
///
/// `unsafe_code` is declared without `report_in_external_macro`, so a use that arrives by
/// expanding a macro from *another* crate is reported nowhere -- not in the crate that
/// wrote it, because a macro body is not analysed where it is defined, and not in the crate
/// that expanded it, because the lint suppresses it there. A security review measured the
/// whole path: three raw pointer reads in a crate that denies `unsafe`, zero diagnostics.
///
/// No crate here exports a macro, and this keeps it that way. It searches for one literal
/// and fails on any occurrence, in code or in a comment, because the point is not to decide
/// what an occurrence means -- reading text to decide that is the mistake this whole gate
/// was rewritten to stop making -- but to make a person decide it. If an exported macro is
/// ever wanted, the decision goes in `APPROVED`'s sibling here with what was done instead.
export function exportedMacros(base = root, list = sources, read = (path) => readFileSync(path, 'utf8')) {
  const reasons = [];
  for (const path of list(resolvePath(base, 'crates'))) {
    if (!read(path).includes('macro_export')) continue;
    reasons.push(
      `${path.replace(`${base.replaceAll('\\', '/')}/`, '')} mentions macro_export: a macro ` +
      'exported to another crate can carry `unsafe` that the compiler reports nowhere',
    );
  }
  return reasons;
}

/// Target kinds this gate does not run, which is not the same as nothing to say about them.
///
/// A build script is the highest-privilege code in the tree -- it runs at build time with
/// the machine's full authority -- and a proc-macro runs inside the compiler. Neither is
/// compiled by the invocations below, and both used to be skipped in silence, so the
/// summary spoke for targets nobody had looked at. A security review named it. There are
/// none in this workspace; if one appears, the gate stops until somebody decides how it is
/// audited.
export function unauditableTargets(metadata) {
  const reasons = [];
  const known = new Set(['lib', 'bin', 'test', 'bench', 'example']);
  for (const pkg of metadata.packages ?? []) {
    for (const target of pkg.targets ?? []) {
      const [kind] = target.kind;
      if (known.has(kind)) continue;
      reasons.push(`${pkg.name} has a ${kind} target (${target.name}) that this gate does not compile`);
    }
  }
  return reasons;
}

/// Every target in the workspace, as the flags `cargo rustc` needs to select one.
///
/// One target per invocation, because `cargo rustc` refuses extra arguments when more
/// than one target is selected -- and the extra argument is the whole point.
export function targetsFrom(metadata) {
  const targets = [];
  for (const pkg of metadata.packages ?? []) {
    for (const target of pkg.targets ?? []) {
      const [kind] = target.kind;
      if (kind === 'custom-build') continue;
      const flag = { lib: ['--lib'], bin: ['--bin', target.name], test: ['--test', target.name],
        bench: ['--bench', target.name], example: ['--example', target.name] }[kind];
      if (!flag) continue;
      targets.push({ package: pkg.name, kind, name: target.name, flags: flag });
      // **And the same target again as its own test harness**, because that is a
      // different configuration of the same file. `cargo rustc --lib` compiles without
      // `cfg(test)`, so an `unsafe` block inside `#[cfg(test)] mod tests` is invisible
      // to it -- and a test module is a place where somebody reaches for a native call
      // to set something up. A security review pointed out the hole. `--profile test`
      // with `--test` is how cargo builds that harness, and it is where the crate's
      // dev-dependencies are available.
      // A `test` target is already a harness -- cargo passes `--test` to rustc for it,
      // and passing it twice is an error, which is how this was found. What needs the
      // extra pass is a lib or a bin, whose `#[cfg(test)]` modules are compiled only
      // into a harness cargo builds separately.
      if (target.test && (kind === 'lib' || kind === 'bin')) {
        targets.push({
          package: pkg.name,
          kind: `${kind} (as its test harness)`,
          name: target.name,
          // `--profile test` is enough: cargo builds the target's harness for it and
          // passes `--test` to rustc itself. Passing it again is an error, which is how
          // this was found -- twice, because a `test` target is a harness already.
          flags: [...flag, '--profile', 'test'],
        });
      }
    }
  }
  return targets;
}

/// Cargo, from the project's own toolchain or from PATH.
///
/// **A missing `.tools/cargo` is not a missing cargo.** The first version of this gate
/// looked only under `.tools/`, which is where `docs/development.md` keeps Rust so a
/// machine's own installation is untouched -- and CI has no `.tools/` at all, so the
/// gate failed on all three platforms before a single Rust test ran. The project's
/// toolchain is preferred where it exists, and PATH is used where it does not.
export function resolveCargo(base = root, exists = existsSync) {
  const local = resolvePath(base, '.tools/cargo/bin', process.platform === 'win32' ? 'cargo.exe' : 'cargo');
  if (process.env.FHD_CARGO) return process.env.FHD_CARGO;
  return exists(local) ? local : 'cargo';
}

function main() {
  const cargo = resolveCargo();
  const listed = spawnSync(cargo, ['metadata', '--no-deps', '--format-version', '1'], {
    cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  if (listed.error || listed.status !== 0) {
    console.error(`could not list the workspace: ${listed.error?.message ?? listed.stderr}`);
    process.exitCode = 1;
    return;
  }
  const metadata = JSON.parse(listed.stdout);
  const targets = targetsFrom(metadata);
  const sites = [];
  const reasons = [...unauditableTargets(metadata), ...exportedMacros()];
  for (const target of targets) {
    const run = spawnSync(
      cargo,
      ['rustc', '-p', target.package, ...target.flags,
        ...(target.flags.includes('--profile') ? [] : ['--profile', 'check']),
        '--message-format=json', '--', '-F', 'unsafe_code', ...(target.rustc ?? [])],
      { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 },
    );
    if (run.error) {
      reasons.push(`${target.package} ${target.kind} ${target.name}: could not run cargo: ${run.error.message}`);
      continue;
    }
    const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;
    const found = sitesFrom(output);
    sites.push(...found);
    for (const reason of auditFailed({
      status: run.status, signal: run.signal, sites: found, reasons: unaudited(output), output,
      expectFinished: true,
    })) {
      reasons.push(`${target.package} ${target.kind} ${target.name}: ${reason}`);
    }
  }
  // **One place in the source is one site, however many configurations compiled it.** Every
  // file is now audited more than once -- as itself and as its own test harness, and a
  // lib also through each target that links it -- so the same `unsafe` block comes back
  // from several invocations. Counting them all would double every number and report
  // every allowance twice.
  const seen = new Map();
  for (const site of sites) seen.set(siteKey(site), site);
  const messages = findings({ sites: [...seen.values()], platform: process.platform });
  if (reasons.length || messages.length) {
    console.error(`Unsafe policy failed on ${process.platform}:`);
    for (const reason of reasons) {
      console.error(`  a target could not be audited: ${reason}`);
    }
    for (const message of messages) console.error(`  ${message}`);
    process.exitCode = 1;
    return;
  }
  const unique = [...seen.values()];
  const allowances = unique.filter((site) => site.kind === 'allowance').length;
  console.log(
    `Unsafe policy: the compiler found ${allowances} allowance(s) and ` +
    `${unique.length - allowances} use(s) of unsafe across ${targets.length} targets on ` +
    `${process.platform}, and every one is approved at the count recorded for it.`,
  );
}

if (process.argv[1] && resolvePath(process.argv[1]) === fileURLToPath(import.meta.url)) main();
