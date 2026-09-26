import { test } from 'node:test';
import assert from 'node:assert/strict';
import { coverageFailures, summaryOf, testsIn } from './check-contract-tests.mjs';

const required = new Map([
  ['on_both', ['win32', 'linux']],
  ['linux_only', ['linux']],
]);

// The whole point of the gate: cargo exits 0 in each of these cases, so the step
// it guards would be green while the property went unmeasured.
test('a required test that did not run is reported, however it stopped running', () => {
  // Nothing ran at all -- the case that actually happened on ubuntu.
  const nothing = coverageFailures({
    platform: 'linux',
    required,
    declared: ['on_both', 'linux_only'],
    listed: [],
    summary: { passed: 0, failed: 0, ignored: 0 },
  });
  assert.equal(nothing.filter(one => /does not contain it/u.test(one)).length, 2, nothing.join('\n'));

  // Compiled but ignored: listed, and the run reports it as ignored.
  const ignored = coverageFailures({
    platform: 'linux',
    required,
    declared: ['on_both', 'linux_only'],
    listed: ['on_both', 'linux_only'],
    summary: { passed: 1, failed: 0, ignored: 1 },
  });
  assert.ok(ignored.some(one => /were ignored/u.test(one)), ignored.join('\n'));
  assert.ok(ignored.some(one => /1 tests passed on linux and 2 are required/u.test(one)));

  // A cfg hid one: absent from the listing, and the count is short.
  const hidden = coverageFailures({
    platform: 'linux',
    required,
    declared: ['on_both', 'linux_only'],
    listed: ['on_both'],
    summary: { passed: 1, failed: 0, ignored: 0 },
  });
  assert.ok(hidden.some(one => /linux_only: required on linux/u.test(one)), hidden.join('\n'));

  // And cargo printing no summary at all is not silence to pass on.
  const quiet = coverageFailures({
    platform: 'linux',
    required,
    declared: ['on_both', 'linux_only'],
    listed: ['on_both', 'linux_only'],
    summary: null,
  });
  assert.ok(quiet.some(one => /no "test result:" line/u.test(one)), quiet.join('\n'));
});

test('a platform where a test is not required does not have to run it', () => {
  assert.deepEqual(
    coverageFailures({
      platform: 'win32',
      required,
      declared: ['on_both', 'linux_only'],
      listed: ['on_both'],
      summary: { passed: 1, failed: 0, ignored: 0 },
    }),
    [],
  );
});

// The other direction: a property added and left out of the specification would
// otherwise be governed by nothing.
test('a test the specification does not name is reported', () => {
  const failures = coverageFailures({
    platform: 'win32',
    required,
    declared: ['on_both', 'linux_only', 'nobody_declared_me'],
    listed: ['on_both', 'nobody_declared_me'],
    summary: { passed: 2, failed: 0, ignored: 0 },
  });
  assert.ok(failures.some(one => /nobody_declared_me: a #\[test\]/u.test(one)), failures.join('\n'));
});

// macOS refuses publication, so zero is the right number there -- and is checked
// rather than assumed, so the day one compiles somebody has to decide why.
test('macOS must compile none of them, and is told when it compiles one', () => {
  assert.deepEqual(
    coverageFailures({
      platform: 'darwin', required, declared: ['on_both', 'linux_only'], listed: [], summary: null,
    }),
    [],
  );
  const appeared = coverageFailures({
    platform: 'darwin',
    required,
    declared: ['on_both', 'linux_only'],
    listed: ['on_both'],
    summary: null,
  });
  assert.equal(appeared.length, 1, appeared.join('\n'));
  assert.match(appeared[0], /macOS compiled 1 publication-contract tests/u);
});

test('a failing test is a failure, not only a missing one', () => {
  const failures = coverageFailures({
    platform: 'win32',
    required,
    declared: ['on_both', 'linux_only'],
    listed: ['on_both'],
    summary: { passed: 0, failed: 1, ignored: 0 },
  });
  assert.ok(failures.some(one => /1 tests failed/u.test(one)), failures.join('\n'));
});

test('an empty requirement for a real platform is refused rather than passed', () => {
  const failures = coverageFailures({
    platform: 'linux',
    required: new Map([['somewhere_else', ['win32']]]),
    declared: ['somewhere_else'],
    listed: [],
    summary: { passed: 0, failed: 0, ignored: 0 },
  });
  assert.equal(failures.length, 1, failures.join('\n'));
  assert.match(failures[0], /no publication-contract test is required on linux/u);
});

test('reads every test in a source, whatever sits between the attribute and the item', () => {
  const source = [
    '#[test]',
    'fn plain() {}',
    '',
    '#[test]',
    '#[cfg(target_os = "linux")]',
    '/// a doc comment in between',
    '// and a line comment',
    'fn behind_attributes_and_comments() {}',
    '',
    '// not a test',
    'fn helper() {}',
    '',
    '#[test]',
    'fn takes_arguments(_: u8) {}',
  ].join('\n');
  assert.deepEqual(testsIn(source), ['plain', 'behind_attributes_and_comments', 'takes_arguments']);
});

test('reads the counts cargo prints, and says so when there are none', () => {
  const output = [
    'running 3 tests',
    'test a ... ok',
    'test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.1s',
  ].join('\n');
  assert.deepEqual(summaryOf(output), { passed: 2, failed: 0, ignored: 1 });
  // A failed run prints `FAILED`, not `ok`, and its counts still have to be read.
  const failed = 'test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out;';
  assert.deepEqual(summaryOf(failed), { passed: 1, failed: 2, ignored: 0 });
  assert.equal(summaryOf('error: could not compile'), null);
});
