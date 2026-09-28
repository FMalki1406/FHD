// Everything a Windows box can check before a push, reporting an exit code per step.
//
// **Why this exists.** A push failed CI at the architecture gate, and the local run
// before it had failed too -- unseen, because I was reading a filtered log for the
// lines each step prints *on success*. A filter that matches success signals makes a
// failure look like silence: the gate's own findings begin with a file path, so they
// matched nothing, and the absent "rules passed" matched nothing either. So this
// reports `name=exit code` for every step and decides from the codes.
//
// **Why Node rather than the PowerShell it replaces.** The first version was a
// PowerShell script, and an independent review found the same class of defect in it:
// where `cargo` or `node` is missing, PowerShell raises a command-not-found error and
// `$LASTEXITCODE` keeps whatever the previous step left there -- zero -- so a step
// that never ran was reported as having passed. That is the bug this tool exists to
// prevent, in the tool itself. Here the spawn result is the evidence: a command that
// could not be launched has no exit code, and `runStep` calls that a failure with a
// reason. And it can be tested the way the gates are, which the PowerShell could not.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));

/// The project-local toolchain, or whatever is on PATH where there is none.
///
/// `docs/development.md` keeps Rust under `.tools/` so a machine's own installation is
/// untouched. A checkout without it -- CI, or a machine with standard Rust -- uses
/// `cargo` from PATH, and if that is missing too the step fails as a step rather than
/// as a crash.
export function toolchain(base = root) {
  const home = join(base, '.tools', 'cargo');
  const local = join(home, 'bin', process.platform === 'win32' ? 'cargo.exe' : 'cargo');
  if (!existsSync(local)) return { cargo: 'cargo', env: process.env };
  return {
    cargo: local,
    env: {
      ...process.env,
      CARGO_HOME: home,
      RUSTUP_HOME: join(base, '.tools', 'rustup'),
    },
  };
}

/// Runs one step and reports what happened, never guessing.
///
/// `{ ok, code, reason }`: `ok` is true only when the command ran **and** exited zero.
/// A command that could not be launched at all -- missing executable, no permission --
/// comes back `ok: false` with `code: null` and the reason, because "it did not run"
/// and "it passed" are the two answers a verification tool must never confuse.
export function runStep(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? root,
    env: options.env ?? process.env,
    encoding: 'utf8',
    shell: false,
    maxBuffer: 256 * 1024 * 1024,
  });
  if (result.error) {
    return { ok: false, code: null, reason: `could not run ${command}: ${result.error.message}`, output: '' };
  }
  if (result.signal) {
    return {
      ok: false,
      code: null,
      reason: `${command} was killed by ${result.signal}`,
      output: `${result.stdout ?? ''}${result.stderr ?? ''}`,
    };
  }
  if (typeof result.status !== 'number') {
    return { ok: false, code: null, reason: `${command} reported no exit status`, output: '' };
  }
  return {
    ok: result.status === 0,
    code: result.status,
    reason: result.status === 0 ? '' : `exit ${result.status}`,
    output: `${result.stdout ?? ''}${result.stderr ?? ''}`,
  };
}

/// The one-line verdict, and the failed steps named with the separator they need.
///
/// The separator is here because the first version built the list with
/// `($failed | ForEach-Object { $_.Key }) -join ', '`, where the join bound to the last
/// element rather than the sequence and the names came out run together. A review
/// caught it as a display defect; it is in a test now because a summary nobody can
/// read is a summary that gets ignored.
export function summarise(steps) {
  const failed = steps.filter((step) => !step.ok);
  if (failed.length === 0) return { ok: true, line: 'every step passed' };
  return {
    ok: false,
    line: `FAILED: ${failed.map((step) => `${step.name} (${step.reason})`).join(', ')}`,
  };
}

/// Tests passed and ignored, totalled from every `test result:` line.
export function testTotals(output) {
  let passed = 0;
  let ignored = 0;
  for (const found of output.matchAll(/test result: \w+\. (\d+) passed; \d+ failed; (\d+) ignored/gu)) {
    passed += Number(found[1]);
    ignored += Number(found[2]);
  }
  return { passed, ignored };
}

/// The steps, in the order a failure is most usefully found.
export function plan({ cargo, skipTests }) {
  const steps = [
    ['fmt', cargo, ['fmt', '--all', '--', '--check']],
    ['clippy-windows', cargo, ['clippy', '--workspace', '--all-targets', '--', '-D', 'warnings']],
    // The crates a Windows box can cross-check: `libsqlite3-sys` needs a C cross
    // compiler, so the daemon and the repository cannot be built for another target
    // here. This is the step that caught a Linux-only test file still calling an old
    // signature after everything Windows compiles was already green.
    ['clippy-linux', cargo, [
      'clippy', '-p', 'fhd-app', '-p', 'fhd-domain', '-p', 'fhd-storage', '-p', 'fhd-runtime',
      '-p', 'fhd-testkit', '-p', 'fhd-platform', '--lib', '--tests',
      '--target', 'x86_64-unknown-linux-gnu', '--', '-D', 'warnings',
    ]],
    ['clippy-macos', cargo, [
      'clippy', '-p', 'fhd-platform', '--all-targets',
      '--target', 'x86_64-apple-darwin', '--', '-D', 'warnings',
    ]],
    ['architecture-gate', process.execPath, ['tools/check-architecture.mjs']],
    ['architecture-gate-tests', process.execPath, ['tools/check-architecture.test.mjs']],
    ['coverage-gate-tests', process.execPath, ['tools/check-contract-tests.test.mjs']],
    ['coverage-gate', process.execPath, ['tools/check-contract-tests.mjs']],
  ];
  if (!skipTests) steps.push(['tests', cargo, ['test', '--workspace']]);
  return steps;
}

function main() {
  const skipTests = process.argv.includes('--skip-tests');
  const { cargo, env } = toolchain();
  // The gates shell out to cargo themselves, so it has to be findable by name too.
  const onPath = { ...env, PATH: `${dirname(cargo)}${process.platform === 'win32' ? ';' : ':'}${env.PATH}` };
  const done = [];
  let output = '';
  for (const [name, command, args] of plan({ cargo, skipTests })) {
    const step = runStep(command, args, { env: onPath });
    done.push({ name, ...step });
    output += step.output;
    process.stdout.write(`${step.ok ? 'ok  ' : 'FAIL'} ${name}${step.ok ? '' : ` -- ${step.reason}`}\n`);
    if (!step.ok) process.stderr.write(step.output);
  }
  const verdict = summarise(done);
  const totals = testTotals(output);
  process.stdout.write(`\n${verdict.line}\n`);
  if (verdict.ok) {
    process.stdout.write(`tests: ${totals.passed} passed, ${totals.ignored} ignored\n`);
  }
  process.exitCode = verdict.ok ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
