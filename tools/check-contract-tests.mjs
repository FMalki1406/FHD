// Every publication-contract test runs, on the platform that claims it.
//
// The contract's evidence is read from CI step names, because the job logs need
// a token this project does not use. `cargo test --test publication` going green
// is therefore the whole claim -- and it goes green when the binary contains no
// tests, when a test is `#[ignore]`d, and when a `cfg` quietly stops compiling
// one. All three have happened here: the step named "Test the publication
// contract" ran **zero tests on ubuntu and exited zero**, so the substitution
// attack, the folder swap, the seal after a crash and the refusal contract were
// all unmeasured on the platform that had just been given a mechanism.
//
// A security review pointed out that the fix for that was a one-off log read:
// somebody counted ten tests once, and nothing kept counting.
//
// **The list below is a specification, not a mirror of the source.** It is
// deliberately not derived from the `#[cfg]` attributes, because then a test
// hidden behind a narrower `cfg` would simply stop being required -- which is
// the failure it exists to catch. Changing it is an edit to this file, which is
// reviewed. The check in the other direction is here too: a `#[test]` in the
// source that this list does not name is a failure, so a new property cannot be
// added and left out of the specification.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SOURCE = 'crates/bins/daemon/tests/publication.rs';
const PACKAGE = 'fhd-daemon';
const TARGET = 'publication';

/// name -> the platforms it must run and pass on.
///
/// `macos` is absent from every entry on purpose, and the file is `cfg`'d off
/// there: macOS refuses publication with `Unsupported`, so there is no
/// publication to hold to a contract. That is asserted rather than assumed --
/// on macOS this script requires the binary to contain **exactly zero** tests,
/// so the day one compiles there, this fails and somebody has to decide what it
/// means instead of reading a green step.
export const REQUIRED = new Map([
  ['publication_carries_the_proved_bytes_though_the_source_name_is_taken', ['win32', 'linux']],
  ['publication_never_replaces_a_file_that_is_already_there', ['win32', 'linux']],
  ['the_window_after_the_last_read_belongs_to_whoever_can_write_the_inode', ['win32', 'linux']],
  ['a_destination_folder_swapped_at_the_boundary_publishes_nowhere_else', ['win32', 'linux']],
  ['a_refused_publication_leaves_the_part_writable_on_the_next_run', ['win32', 'linux']],
  ['a_folder_swapped_before_adoption_is_the_one_adopted_and_that_is_the_window', ['win32', 'linux']],
  ['a_refused_publication_keeps_the_progress_allows_a_retry_and_touches_nothing_else', ['win32', 'linux']],
  ['a_location_check_that_cannot_be_completed_is_not_reported_as_a_move', ['win32', 'linux']],
  ['a_part_that_has_published_refuses_to_publish_again_and_keeps_its_seal', ['win32', 'linux']],
  ['a_part_found_sealed_after_a_crash_neither_publishes_nor_loses_its_seal', ['win32', 'linux']],
  // Linux only: it needs a FIFO at the requested path, and Windows filesystem
  // paths hold none.
  ['a_fifo_at_the_requested_path_does_not_hang_publication', ['linux']],
  ['a_parts_directory_swapped_for_a_fifo_does_not_hang_publication_after_delivery', ['linux']],
  ['a_symlink_at_the_requested_name_pointing_at_the_part_is_not_reported_as_at', ['linux']],
  ['a_failed_location_check_after_the_link_keeps_the_seal_and_the_files', ['win32', 'linux']],
]);

/// Runs cargo and returns its output whether it succeeded or not.
///
/// `execFileSync` throws on a non-zero exit, and the throw carried cargo's
/// **stderr** in the message while the run's stdout -- the `test … FAILED` lines,
/// the panic messages, the `test result:` line -- sat on `error.stdout` and was
/// dropped. So a regressed property made this step print a Node stack trace and
/// the compile log, and nothing about which property failed. An engineering
/// review measured the shape of the throw and pointed out that this was a loss
/// against the plain `cargo test` it replaced, in a project whose whole evidence
/// model is reading CI steps. Returning the output instead also makes the
/// `failed !== 0` branch reachable rather than dead.
let nonZeroExit = 0;
function cargo(extra) {
  const argv = ['+1.98.1', 'test', '-p', PACKAGE, '--test', TARGET, '--locked', ...extra];
  try {
    return execFileSync('cargo', argv, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  } catch (error) {
    // A failing test run: cargo exits non-zero and its output is the finding.
    //
    // The exit code is remembered rather than discarded. An engineering review
    // pointed out that reading only the parsed `test result:` line lets a run that
    // prints a clean summary and *then* exits non-zero -- a harness abort, a crash
    // in a global destructor, a leaked thread -- pass a gate that the plain
    // `cargo test` it replaced would have failed.
    if (typeof error.stdout === 'string' && error.stdout) {
      process.stderr.write(error.stdout);
      if (typeof error.stderr === 'string') process.stderr.write(error.stderr);
      nonZeroExit = error.status ?? 1;
      return error.stdout;
    }
    // No output at all means cargo never ran the tests -- missing toolchain, a
    // compile error, a `maxBuffer` overrun. Nothing to summarise, so say what
    // happened and fail rather than report a count of zero as a finding.
    console.error(`cargo could not be run or could not build: ${error.message}`);
    if (typeof error.stderr === 'string') console.error(error.stderr);
    process.exit(1);
  }
}

/// Every `#[test]` in the source, whatever `cfg` sits on it.
///
/// This is the half of the gate that catches a property added and never declared,
/// so anything it fails to see is a hole. The first version saw only a bare
/// `#[test]` line and then broke out of its scan at the first line that was not a
/// comment or a complete `#[…]` attribute -- so an engineering review got two
/// shapes past it by measurement: a **multi-line** attribute between `#[test]`
/// and the `fn` (the scan stopped on the continuation line), and any trailing
/// text on the `#[test]` line itself. Either one made a contract test invisible
/// here, and if its `cfg` also kept it off every CI platform it ran nowhere while
/// this gate stayed green.
///
/// So the scan now tracks bracket depth instead of matching whole lines, and
/// strips comments rather than skipping only lines that begin with one.
export function testsIn(text) {
  const names = [];
  const lines = text.split('\n');
  // `/* */` nests in Rust; only comment state has to survive between lines.
  let depth = 0;
  const strip = (line) => {
    let out = '';
    for (let index = 0; index < line.length; index += 1) {
      if (depth === 0 && line.startsWith('//', index)) break;
      if (line.startsWith('/*', index)) { depth += 1; index += 1; continue; }
      if (depth > 0 && line.startsWith('*/', index)) { depth -= 1; index += 1; continue; }
      if (depth === 0) out += line[index];
    }
    return out;
  };
  for (let index = 0; index < lines.length; index += 1) {
    if (strip(lines[index]).trim() !== '#[test]') continue;
    // Walk forward over attributes -- however many lines each one spans -- and
    // blank or comment-only lines, to the item they sit on.
    let brackets = 0;
    for (let scan = index + 1; scan < lines.length; scan += 1) {
      const line = strip(lines[scan]).trim();
      if (!line) continue;
      if (brackets === 0 && !line.startsWith('#')) {
        const found = /^(?:pub(?:\([^)]*\))? )?(?:async )?fn ([A-Za-z0-9_]+)\s*(?:<|\()/u.exec(line);
        if (found) names.push(found[1]);
        break;
      }
      for (const character of line) {
        if (character === '[' || character === '(') brackets += 1;
        if (character === ']' || character === ')') brackets -= 1;
      }
      if (brackets < 0) brackets = 0;
    }
  }
  return names;
}

/// The failures, as messages. Exported so the shape is testable without cargo.
export function coverageFailures({ platform, required, declared, listed, summary }) {
  const failures = [];
  const wanted = [...required.entries()]
    .filter(([, platforms]) => platforms.includes(platform))
    .map(([name]) => name)
    .sort();

  for (const name of declared) {
    if (!required.has(name)) {
      failures.push(
        `${name}: a #[test] in ${SOURCE} that tools/check-contract-tests.mjs does not ` +
        'name. Add it to REQUIRED with the platforms it must run on.',
      );
    }
  }

  if (platform === 'darwin') {
    // macOS refuses publication, so there is no contract to run. Asserted, not
    // assumed: if one ever compiles here, say so rather than pass.
    if (listed.length !== 0) {
      failures.push(
        `macOS compiled ${listed.length} publication-contract tests (${listed.join(', ')}). ` +
        'macOS refuses publication with Unsupported, so this list is expected to be ' +
        'empty. Decide what these measure before letting the step go green.',
      );
    }
    return failures;
  }

  if (wanted.length === 0) {
    failures.push(`no publication-contract test is required on ${platform}, which cannot be right`);
    return failures;
  }
  for (const name of wanted) {
    if (!listed.includes(name)) {
      failures.push(
        `${name}: required on ${platform} and the binary does not contain it. ` +
        'A cfg is hiding it, or it was renamed or deleted.',
      );
    }
  }
  if (!summary) {
    failures.push('cargo printed no "test result:" line, so nothing is known about what ran');
    return failures;
  }
  if (summary.passed !== wanted.length) {
    failures.push(
      `${summary.passed} tests passed on ${platform} and ${wanted.length} are required. ` +
      'A required test did not run.',
    );
  }
  if (summary.failed !== 0) failures.push(`${summary.failed} tests failed`);
  if (summary.ignored !== 0) {
    failures.push(
      `${summary.ignored} tests were ignored. #[ignore] leaves the run green and the ` +
      'property unmeasured, which is the case this check exists for.',
    );
  }
  return failures;
}

export function summaryOf(output) {
  const found = /^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored/mu.exec(output);
  if (!found) return null;
  return {
    passed: Number(found[1]),
    failed: Number(found[2]),
    ignored: Number(found[3]),
  };
}

function main() {
  const declared = testsIn(readFileSync(SOURCE, 'utf8'));
  const listed = cargo(['--', '--list'])
    .split('\n')
    .map((line) => /^([a-z0-9_:]+): test$/u.exec(line.trim()))
    .filter(Boolean)
    .map((found) => found[1].replace(/^tests::/u, ''));
  // On macOS the binary has no tests, so running it proves nothing and the
  // listing is the whole check.
  const summary = process.platform === 'darwin' ? null : summaryOf(cargo([]));
  const failures = coverageFailures({
    platform: process.platform,
    required: REQUIRED,
    declared,
    listed,
    summary,
  });
  if (nonZeroExit !== 0) {
    failures.push(
      `cargo exited ${nonZeroExit} although the summary above was read. A run can ` +
      'print clean counts and then abort, and the step this guards must not pass on it.',
    );
  }
  if (failures.length) {
    console.error(`Publication contract coverage failed on ${process.platform}:`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exitCode = 1;
    return;
  }
  const count = process.platform === 'darwin' ? 0 : summary.passed;
  console.log(
    `Publication contract: ${count} of ${count} required tests ran and passed on ` +
    `${process.platform}, 0 ignored.`,
  );
}

// The same guard `check-architecture.mjs` uses: a suffix test would also match
// this file's own test file on a less careful day, and importing it would then
// shell out to cargo.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
