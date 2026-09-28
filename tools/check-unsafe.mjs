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
//   * the `unsafe_code` lint for every use of `unsafe`, wherever it is.
//
// Nothing here parses Rust. What it does is compare two sets: the allowances the
// compiler found, and the allowances this file approves.
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
import { readFileSync } from 'node:fs';
import { dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

/// Every approved allowance, with the platforms whose compiler should report it.
///
/// **The platforms are part of the entry now.** There is one implementation of the
/// linker per system and three unwired macOS primitives, so an entry that is absent on
/// Windows may be perfectly present on macOS. The scanner read every `cfg` branch at
/// once and could not tell the difference; the compiler tells the truth about one
/// configuration at a time, which means the list has to say which.
///
/// `item` is the text of the item the allowance sits on, as one line. Widening this is
/// an edit to this file, which is reviewed. It is a gate, not the review: an approved
/// entry still needs somebody to have agreed that the call in it is sound.
export const APPROVED = new Map([
  ['crates/adapters/platform/src/lib.rs', [
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
    // `clone_into_directory` calls `fclonefileat(2)` on macOS, `open_in_directory`
    // calls `openat(2)`, and `move_into_directory` calls `renameatx_np`: the three
    // steps of the candidate macOS path. All take borrowed descriptors and names owned
    // here, and all are measured rather than adopted -- nothing in the engine calls
    // them, and the publication contract says what adopting them would require first.
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
  ]],
]);

/// Uses of `unsafe` that were already in the tree when this gate could first see them.
///
/// **These are recorded, not approved.** Neither crate declares `deny(unsafe_code)` or
/// `forbid(unsafe_code)`, so its `unsafe` needs no allowance attribute -- which is
/// exactly why the attribute scanner this gate replaces was structurally unable to see
/// them. The architecture rules say `fhd-platform` is the only crate that may use
/// `unsafe`; these two have been outside that rule, unreported, for as long as the rule
/// has existed.
///
/// What this list is for is a ratchet, not an absolution: the count per file is pinned,
/// so a **new** use fails the gate, and a use that goes away fails it too -- the list
/// stays a description of the tree. The gate's success line states the total, so the
/// debt is read out on every run rather than filed away.
///
/// What each one is, for whoever picks this up:
///
/// * `platform-files`: one `GetDiskFreeSpaceExW` behind a NUL-terminated wide buffer,
///   with two documented-nullable out-parameters.
/// * `queue-secrets`: DPAPI `CryptProtectData`/`CryptUnprotectData` and one
///   `slice::from_raw_parts` over the blob they return.
///
/// **Closing it is one of two things**, and both need a security review rather than an
/// edit here: bring them under the same mechanism as `fhd-platform` -- a crate-level
/// `deny` and an `#[allow(unsafe_code)]` on the one item, which this gate then requires
/// to be approved by signature -- or move the calls into `fhd-platform`, where the
/// `unsafe` boundary already lives.
export const INHERITED = new Map([
  ['crates/platform-files/src/lib.rs', 1],
  ['crates/queue-secrets/src/lib.rs', 3],
]);

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
      text: (primary.text?.[0]?.text ?? '').trim(),
    });
  }
  return sites;
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
    if (code === 'E0453' || code === 'unsafe_code') continue;
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
export function findings({
  sites,
  approved = APPROVED,
  inherited = INHERITED,
  platform,
  name = itemAt,
}) {
  const messages = [];
  const uses = new Map();
  const expected = new Map();
  for (const [file, entries] of approved) {
    const wanted = entries.filter((entry) => entry.platforms.includes(platform));
    if (wanted.length) expected.set(file, wanted.map((entry) => entry.item));
  }
  const matched = new Map([...expected].map(([file, items]) => [file, [...items]]));

  for (const site of sites) {
    if (site.kind === 'usage') {
      // A use of `unsafe` in a file that approves nothing. No attribute-based scan can
      // see this: a crate that declares no restriction needs no allowance to use it.
      if (approved.has(site.file)) continue;
      uses.set(site.file, (uses.get(site.file) ?? 0) + 1);
      if (!inherited.has(site.file)) {
        messages.push(
          `${site.file}:${site.line}: unsafe is used in a file that approves none, and ` +
          `this file is not one of the recorded inherited ones. ${site.text}`,
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

  // The ratchet: the recorded count is what the tree has, no more and no less.
  for (const [file, recorded] of inherited) {
    const found = uses.get(file) ?? 0;
    if (found !== recorded) {
      messages.push(
        `${file}: ${found} use(s) of unsafe, and ${recorded} recorded as inherited. ` +
        'A new one needs a review before it is recorded; one that has gone needs the ' +
        'count corrected, so the list stays a description of the tree.',
      );
    }
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
  return messages;
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
  return { sites: sitesFrom(output), reasons: unaudited(output) };
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
    }
  }
  return targets;
}

function main() {
  const cargo = process.env.FHD_CARGO
    ?? resolvePath(root, '.tools/cargo/bin', process.platform === 'win32' ? 'cargo.exe' : 'cargo');
  const listed = spawnSync(cargo, ['metadata', '--no-deps', '--format-version', '1'], {
    cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  if (listed.error || listed.status !== 0) {
    console.error(`could not list the workspace: ${listed.error?.message ?? listed.stderr}`);
    process.exitCode = 1;
    return;
  }
  const targets = targetsFrom(JSON.parse(listed.stdout));
  const sites = [];
  const reasons = [];
  for (const target of targets) {
    const run = spawnSync(
      cargo,
      ['rustc', '-p', target.package, ...target.flags, '--profile', 'check',
        '--message-format=json', '--', '-F', 'unsafe_code'],
      { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 },
    );
    if (run.error) {
      reasons.push(`${target.package} ${target.kind} ${target.name}: could not run cargo: ${run.error.message}`);
      continue;
    }
    const output = `${run.stdout ?? ''}${run.stderr ?? ''}`;
    sites.push(...sitesFrom(output));
    for (const reason of unaudited(output)) {
      reasons.push(`${target.package} ${target.kind} ${target.name}: ${reason}`);
    }
  }
  const messages = findings({ sites, platform: process.platform });
  if (reasons.length || messages.length) {
    console.error(`Unsafe policy failed on ${process.platform}:`);
    for (const reason of reasons) {
      console.error(`  a target could not be audited: ${reason}`);
    }
    for (const message of messages) console.error(`  ${message}`);
    process.exitCode = 1;
    return;
  }
  const allowances = sites.filter((site) => site.kind === 'allowance').length;
  const debt = [...INHERITED.values()].reduce((total, one) => total + one, 0);
  console.log(
    `Unsafe policy: the compiler found ${allowances} approved allowance(s) and ` +
    `${sites.length - allowances} use(s) of unsafe across ${targets.length} targets on ` +
    `${process.platform}. ${debt} of those uses are recorded as inherited and ` +
    `**not approved** (${[...INHERITED.keys()].join(', ')}); the rest are covered by an ` +
    'approved allowance.',
  );
}

if (process.argv[1] && resolvePath(process.argv[1]) === fileURLToPath(import.meta.url)) main();
