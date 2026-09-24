import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
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
  const walk = (directory) => {
    for (const entry of readdirSync(directory)) {
      if (entry === 'target' || entry === '.git') continue;
      const full = `${directory}/${entry}`;
      if (statSync(full).isDirectory()) { walk(full); continue; }
      if (!entry.endsWith('.rs')) continue;
      const relative = full.slice(root.length + 1).split('\\').join('/');
      offenders.push(...unsafeOffendersIn(relative, readFileSync(full, 'utf8')));
    }
  };
  walk(`${root}/crates`);
  return offenders;
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
  for (const unused of remaining) {
    offenders.push(
      `${relative}: approved unsafe allowance is no longer present: ${unused}. ` +
      'Remove it from UNSAFE_ALLOWANCES so the list stays a description of the tree.',
    );
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
  console.log(`Architecture dependency rules passed (${metadata.workspace_members.length} workspace packages, each named by a test step, unsafe allowances as approved).`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
