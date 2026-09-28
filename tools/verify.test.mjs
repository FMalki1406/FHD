import { test } from 'node:test';
import assert from 'node:assert/strict';
import { plan, runStep, summarise, testTotals, toolchain } from './verify.mjs';

/// A command that cannot be launched is a failure, not a pass.
///
/// **This is the defect the tool exists to prevent, found in the tool.** The first
/// version was a PowerShell script that read `$LASTEXITCODE` after each step: where
/// `cargo` or `node` was missing, PowerShell raised a command-not-found error and that
/// variable kept whatever the previous step had left in it -- zero -- so a step that
/// never ran was reported as having passed. An independent review found it, and it is
/// the same shape as the failure that prompted the tool: something that did not happen
/// reading as something that went well.
test('a command that does not exist is reported as not having run', () => {
  const step = runStep('fhd-no-such-command-exists', ['--version']);
  assert.equal(step.ok, false, 'a missing command was reported as a pass');
  assert.equal(step.code, null, 'a command that never ran was given an exit code');
  assert.match(step.reason, /could not run fhd-no-such-command-exists/u);
});

/// And a command that runs and fails is a failure with its code.
test('an exit code is carried through, zero and non-zero alike', () => {
  const ok = runStep(process.execPath, ['-e', 'process.exit(0)']);
  assert.deepEqual({ ok: ok.ok, code: ok.code }, { ok: true, code: 0 });

  const bad = runStep(process.execPath, ['-e', 'process.exit(3)']);
  assert.deepEqual({ ok: bad.ok, code: bad.code }, { ok: false, code: 3 });
  assert.equal(bad.reason, 'exit 3');

  // Output is kept whichever way it went, so a failure can be read.
  const noisy = runStep(process.execPath, ['-e', 'console.log("spoken"); process.exit(1)']);
  assert.match(noisy.output, /spoken/u);
});

/// The summary names every failed step, separated.
///
/// The separator is asserted because the first version built this list in PowerShell
/// with `(... | ForEach-Object { $_.Key }) -join ', '`, where the join bound to the
/// last element instead of the sequence and the names came out run together. A review
/// caught it. A summary nobody can read is a summary that gets ignored, which is how
/// the failure this tool exists to catch went unnoticed in the first place.
test('the verdict names the failed steps with separators', () => {
  const passing = summarise([
    { name: 'fmt', ok: true },
    { name: 'tests', ok: true },
  ]);
  assert.deepEqual(passing, { ok: true, line: 'every step passed' });

  const failing = summarise([
    { name: 'fmt', ok: true },
    { name: 'architecture-gate', ok: false, reason: 'exit 1' },
    { name: 'tests', ok: false, reason: 'could not run cargo: spawn ENOENT' },
  ]);
  assert.equal(failing.ok, false);
  assert.equal(
    failing.line,
    'FAILED: architecture-gate (exit 1), tests (could not run cargo: spawn ENOENT)',
  );
  // Both names present and not run together, which is the whole point.
  assert.ok(failing.line.includes('), '), failing.line);
});

/// The counts are read off the harness's own lines, not assumed.
test('test totals add up across suites and stay zero when there are none', () => {
  const output = [
    'test result: ok. 12 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out',
    'test result: ok. 30 passed; 0 failed; 13 ignored; 0 measured; 0 filtered out',
  ].join('\n');
  assert.deepEqual(testTotals(output), { passed: 42, ignored: 14 });
  assert.deepEqual(testTotals('nothing ran'), { passed: 0, ignored: 0 });
  // A failing run is not counted as passing.
  assert.deepEqual(
    testTotals('test result: FAILED. 5 passed; 1 failed; 0 ignored'),
    { passed: 5, ignored: 0 },
  );
});

/// Every step is a real step, and the tests can be left out without losing the rest.
test('the plan covers the gates and both cross targets', () => {
  const full = plan({ cargo: 'cargo', skipTests: false }).map(([name]) => name);
  for (const required of [
    'fmt',
    'clippy-windows',
    'clippy-linux',
    'clippy-macos',
    'architecture-gate',
    'architecture-gate-tests',
    'unsafe-gate-tests',
    'unsafe-gate',
    'coverage-gate-tests',
    'coverage-gate',
    'tests',
  ]) {
    assert.ok(full.includes(required), `${required} is not in the plan: ${full.join(', ')}`);
  }
  assert.equal(new Set(full).size, full.length, 'a step is named twice');

  const quick = plan({ cargo: 'cargo', skipTests: true }).map(([name]) => name);
  assert.ok(!quick.includes('tests'));
  assert.equal(quick.length, full.length - 1);

  // Nothing in the plan is spelled through a shell, so no argument is word-split.
  for (const [, , args] of plan({ cargo: 'cargo', skipTests: false })) {
    assert.ok(Array.isArray(args), 'arguments must be a list, not a command line');
  }
});

/// A checkout without the project-local toolchain still names a command to run.
test('the toolchain falls back to PATH rather than to nothing', () => {
  const missing = toolchain('D:/definitely/not/a/checkout');
  assert.equal(missing.cargo, 'cargo');
});
