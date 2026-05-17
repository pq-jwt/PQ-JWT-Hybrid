import { execSync } from 'node:child_process';
import { mkdtempSync, rmSync, cpSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const ecosystemDir = dirname(fileURLToPath(import.meta.url));

function run(cmd, cwd) {
  execSync(cmd, { cwd, stdio: 'inherit', env: process.env });
}

function packTarball() {
  const out = execSync('npm pack --silent', { cwd: root, encoding: 'utf8' }).trim();
  const line = out.split('\n').find((l) => l.endsWith('.tgz')) ?? out.split('\n').pop();
  return resolve(root, line.trim());
}

const consumers = [
  {
    name: 'JavaScript (Node ESM)',
    dir: 'js',
    check: (work) => {
      run(`npm install "${tarball}"`, work);
      run('node app.mjs', work);
    },
  },
  {
    name: 'TypeScript (moduleResolution: NodeNext)',
    dir: 'ts-nodenext',
    check: (work) => {
      run(`npm install "${tarball}" typescript@5`, work);
      run('npx tsc --noEmit', work);
    },
  },
  {
    name: 'TypeScript (moduleResolution: Bundler)',
    dir: 'ts-bundler',
    check: (work) => {
      run(`npm install "${tarball}" typescript@5`, work);
      run('npx tsc --noEmit', work);
    },
  },
];

console.log('Packing @pq-jwt/hybrid from', root);
const tarball = packTarball();
console.log('Tarball:', tarball);

const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
console.log('Package version:', version, '\n');

let failed = 0;

for (const consumer of consumers) {
  const work = mkdtempSync(join(tmpdir(), `pq-jwt-hybrid-${consumer.dir}-`));
  try {
    console.log(`--- ${consumer.name} ---`);
    cpSync(join(ecosystemDir, consumer.dir), work, { recursive: true });
    consumer.check(work);
    console.log(`PASS ${consumer.name}\n`);
  } catch (err) {
    failed++;
    console.error(`FAIL ${consumer.name}\n`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

try {
  rmSync(tarball, { force: true });
} catch {}

if (failed > 0) {
  console.error(`${failed} ecosystem check(s) failed`);
  process.exit(1);
}

console.log('All ecosystem checks passed (JS + TS modern toolchains).');
