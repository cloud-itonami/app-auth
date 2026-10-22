#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const namespace = 'itonami.auth.return-to';
const sourcePath = 'src/itonami/auth/return_to.kotoba';
const lockPath = resolve(repoRoot, 'kotoba/return-to/module-lock.edn');
const blockRoot = resolve(repoRoot, 'kotoba/return-to/blocks');
const outputPath = resolve(repoRoot, 'dist/kotoba-selfhost/return-to.wasm');
const provenancePath = resolve(repoRoot, 'dist/kotoba-selfhost/return-to.wasm.provenance.json');
const expectedCompilerSha256 = 'd37c12ed80f48f601b52da5838e258dd40aaccc248105247625798a0d4b0558b';
const expectedLoaderSha256 = '05798f17613db2936cf8fe29c16590c8c2b7513fc80e5b2334e89d16b482f7aa';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const base32Alphabet = 'abcdefghijklmnopqrstuvwxyz234567';

function base32(bytes) {
  let output = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += base32Alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
      buffer &= (1 << bits) - 1;
    }
  }
  if (bits > 0) output += base32Alphabet[(buffer << (5 - bits)) & 31];
  return `b${output}`;
}

function rawCid(bytes) {
  return base32(Buffer.concat([
    Buffer.from([1, 0x55, 0x12, 0x20]),
    createHash('sha256').update(bytes).digest(),
  ]));
}

function requiredPath(name) {
  const value = process.env[name];
  if (!value) throw new Error(`set ${name} to the pinned AMU selfhost build input`);
  const path = resolve(value);
  if (!existsSync(path)) throw new Error(`${name} does not exist: ${path}`);
  return path;
}

const lockBytes = readFileSync(lockPath);
const lockText = lockBytes.toString('utf8');
const lockMatch = /^\{\s*:schema\s+:kotoba\.module-lock\/v1\s*,\s*:root\s+([A-Za-z0-9._-]+)\s*,\s*:modules\s+\{([\s\S]*)\}\s*\}\s*$/.exec(lockText);
if (!lockMatch || lockMatch[1] !== namespace) throw new Error('return-to module lock has an unsupported root or shape');
const lockEntries = [...lockMatch[2].matchAll(/([A-Za-z0-9._-]+)\s+"(b[a-z2-7]+)"/g)];
if (lockEntries.length !== 1 || lockEntries[0][1] !== namespace) throw new Error('return-to lock must contain exactly its root module');
const canonicalEntries = `${namespace} "${lockEntries[0][2]}"`;
if (lockMatch[2].trim() !== canonicalEntries) throw new Error('return-to lock module map is not canonical');

const sourceBytes = readFileSync(resolve(repoRoot, sourcePath));
const sourceCid = rawCid(sourceBytes);
if (sourceCid !== lockEntries[0][2]) throw new Error('return-to Kotoba source does not match its locked CID');
if (!readFileSync(resolve(blockRoot, sourceCid)).equals(sourceBytes)) throw new Error('return-to block bytes differ from the source');

const compilerPath = requiredPath('AMU_SELFHOST_COMPILER');
const loaderPath = requiredPath('AMU_SELFHOST_LOADER');
const compilerSha256 = sha256(readFileSync(compilerPath));
const loaderSha256 = sha256(readFileSync(loaderPath));
if (compilerSha256 !== expectedCompilerSha256) throw new Error(`unqualified AMU selfhost compiler: ${compilerSha256}`);
if (loaderSha256 !== expectedLoaderSha256) throw new Error(`unqualified AMU selfhost loader: ${loaderSha256}`);

mkdirSync(dirname(outputPath), { recursive: true });
const temporaryOutput = `${outputPath}.tmp`;
const temporaryProvenance = `${provenancePath}.tmp`;
rmSync(temporaryOutput, { force: true });
rmSync(temporaryProvenance, { force: true });
const env = {
  ...process.env,
  KEXE_COMMAND: '1',
  KEXE_CAP_RESOURCES_35: repoRoot,
  KEXE_FUEL: 'off',
  KEXE_VECTORS: '4194304',
  KEXE_VECTOR_ITEMS: '134217728',
  KEXE_STRING_POOL: '268435456',
  KEXE_PAIRS: '16777216',
  KEXE_CPU_SECONDS: '900',
  KEXE_WALL_SECONDS: '900',
  TMPDIR: repoRoot,
};
const args = [
  compilerPath, '0', '0', 'aarch64', '35,37,38,39', '--',
  'compile', sourcePath, '--source-path', 'src', '--unpinned',
  '--target', 'wasm32-browser', '--output', temporaryOutput,
];
const result = spawnSync(loaderPath, args, {
  cwd: repoRoot,
  env,
  encoding: 'utf8',
  stdio: 'inherit',
  timeout: 900_000,
});
if (result.error) throw result.error;
if (result.status !== 0) throw new Error(`AMU selfhost compile exited with status ${result.status ?? 'unknown'}`);

const wasmBytes = readFileSync(temporaryOutput);
if (!WebAssembly.validate(wasmBytes)) throw new Error('selfhost output is not a valid WebAssembly module');
const module = new WebAssembly.Module(wasmBytes);
const imports = WebAssembly.Module.imports(module);
for (const imported of imports) {
  if (imported.kind !== 'function' || imported.module !== 'kotoba') throw new Error(`unexpected import ${imported.module}.${imported.name}`);
}
const exports = WebAssembly.Module.exports(module).map(({ name, kind }) => `${kind}:${name}`);
if (exports.length !== 1 || exports[0] !== 'function:safe-return-to') {
  throw new Error(`unexpected return-to Wasm export set: ${exports.join(', ')}`);
}

const provenance = {
  schema: 'kotoba.amu.selfhost-wasm-module-provenance/v1',
  target: 'wasm32-browser',
  format: 'wasm',
  root: namespace,
  source: { path: sourcePath, cid: sourceCid, sha256: sha256(sourceBytes), bytes: sourceBytes.length },
  moduleLockSha256: sha256(lockBytes),
  lockCid: rawCid(lockBytes),
  lockVerifier: 'fixed-one-module-source-cid-check/v1',
  compilerLockInput: false,
  compilerSha256,
  loaderSha256,
  imports,
  runtimeOpcodes: [72, 112, 136, 144, 248],
  exports,
  artifactSha256: sha256(wasmBytes),
  artifactBytes: wasmBytes.length,
};
writeFileSync(temporaryProvenance, `${JSON.stringify(provenance, null, 2)}\n`);
renameSync(temporaryOutput, outputPath);
renameSync(temporaryProvenance, provenancePath);
process.stdout.write(`${JSON.stringify(provenance, null, 2)}\n`);
