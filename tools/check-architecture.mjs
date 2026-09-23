import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
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
  'fhd-ipc': ['fhd-app', 'fhd-protocol', 'fhd-config', 'fhd-telemetry'],
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
  console.log(`Architecture dependency rules passed (${metadata.workspace_members.length} workspace packages, each named by a test step).`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { main(process.argv.slice(2)); }
  catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
