import { test } from 'node:test';
import assert from 'node:assert/strict';
import { coverageFailures, REQUIRED, summaryOf, testsIn } from './check-contract-tests.mjs';

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

// The two shapes an engineering review got past the first version by
// measurement. Either made a contract test invisible to the undeclared-test
// check, and a `cfg` that also kept it off every CI platform would then have let
// it run nowhere with this gate green.
test('a test cannot hide behind a multi-line attribute or a trailing comment', () => {
  const source = [
    '#[test]',
    '#[cfg(all(',
    '    target_os = "linux",',
    '    feature = "slow",',
    '))]',
    'fn hidden_behind_a_multiline_cfg() {}',
    '',
    '#[test] // a trailing comment on the attribute line',
    'fn attribute_with_trailing_comment() {}',
    '',
    '#[test]',
    '/* a block comment',
    '   over two lines */',
    'fn behind_a_block_comment() {}',
    '',
    '    #[test]',
    '    #[cfg_attr(miri, ignore)]',
    '    fn indented_inside_a_mod() {}',
    '',
    '#[test]',
    'async fn an_async_test() {}',
  ].join('\n');
  assert.deepEqual(testsIn(source), [
    'hidden_behind_a_multiline_cfg',
    'attribute_with_trailing_comment',
    'behind_a_block_comment',
    'indented_inside_a_mod',
    'an_async_test',
  ]);
});

// And it must not start seeing things that are not tests, or the undeclared-test
// check turns into noise nobody reads.
test('does not read a test where there is none', () => {
  const source = [
    '// #[test]',
    'fn commented_out_attribute() {}',
    '',
    '/* #[test]',
    'fn inside_a_block_comment() {} */',
    '',
    'fn no_attribute_at_all() {}',
    '',
    '#[test_case(1)]',
    'fn a_different_attribute() {}',
  ].join('\n');
  assert.deepEqual(testsIn(source), []);
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

// The real specification, on the platform that cannot be mutated from here.
//
// A security review pointed out that the four mutations run against this gate
// were all run on Windows, where the Linux-only properties are not compiled --
// so "the gate requires the FIFO tests on Linux" was correct by reading and
// measured nowhere. This measures it at the level that can be measured from a
// Windows machine: the real `REQUIRED` map, asked the question the gate asks.
test('the real specification requires the Linux-only properties on Linux', () => {
  const linuxOnly = [
    'a_fifo_at_the_requested_path_does_not_hang_publication',
    'a_parts_directory_swapped_for_a_fifo_does_not_hang_publication_after_delivery',
  ];
  for (const name of linuxOnly) {
    assert.deepEqual(REQUIRED.get(name), ['linux'], `${name} is not declared Linux-only`);
  }

  // On Linux, each of them missing from the binary is a failure that names it.
  const listed = [...REQUIRED.entries()]
    .filter(([, platforms]) => platforms.includes('linux'))
    .map(([name]) => name);
  for (const dropped of linuxOnly) {
    const short = listed.filter(name => name !== dropped);
    const failures = coverageFailures({
      platform: 'linux',
      required: REQUIRED,
      declared: [...REQUIRED.keys()],
      listed: short,
      summary: { passed: short.length, failed: 0, ignored: 0 },
    });
    assert.ok(
      failures.some(one => one.startsWith(`${dropped}: required on linux`)),
      `dropping ${dropped} on Linux was not reported: ${failures.join(' | ')}`,
    );
  }

  // And the whole set present, with the matching count, passes.
  assert.deepEqual(
    coverageFailures({
      platform: 'linux',
      required: REQUIRED,
      declared: [...REQUIRED.keys()],
      listed,
      summary: { passed: listed.length, failed: 0, ignored: 0 },
    }),
    [],
  );

  // Windows does not compile them, and must not be asked to.
  for (const name of linuxOnly) {
    assert.ok(!REQUIRED.get(name).includes('win32'), `${name} must not be required on Windows`);
  }
});
