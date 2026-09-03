/** Reconstruct public metadata from verified manifests and a public signature.
 * Does not sign anything, run inference, execute downloaded code or publish a
 * release. The private signing key is neither needed nor accepted here.
 */
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { gunzipSync } from 'node:zlib';

assert.equal(process.argv[2], '--confirmed-signed-component-metadata');
const repository = 'chenjiale364-crypto/haomai-desktop-releases';
assert.equal(process.env.GITHUB_REPOSITORY, repository);
assert.equal(process.env.GITHUB_REF, 'refs/heads/codex/voice-components-cloud');
const token = process.env.GITHUB_TOKEN; assert(token);
const descriptor = JSON.parse(fs.readFileSync(new URL('./metadata-descriptor.json', import.meta.url), 'utf8'));
assert(descriptor.schemaVersion === 1 && descriptor.releaseId === 381995933 && descriptor.tag === 'voice-components-2.5.0-haomai.1');
assert(descriptor.keyId === 'haomai-voice-ed25519-2026-09' && descriptor.publicKey.startsWith('-----BEGIN PUBLIC KEY-----')
  && !descriptor.publicKey.includes('PRIVATE'));
assert.deepEqual(descriptor.manifests.map((item) => item.id), ['indextts-engine', 'indextts-2.5-core', 'qwen-emotion', 'shared-caption-alignment']);
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' };
const apiRoot = `https://api.github.com/repos/${repository}`;
async function api(suffix, method = 'GET') {
  const response = await fetch(apiRoot + suffix, { method, headers, redirect: 'error', signal: AbortSignal.timeout(60_000) });
  assert(response.ok, `GitHub ${method}: HTTP ${response.status}`);
  return response.status === 204 ? null : response.json();
}
async function manifestBytes(asset, expected) {
  assert(asset.state === 'uploaded' && asset.size === expected.bytes && asset.digest === `sha256:${expected.sha256}` && asset.size < 5 * 1024 ** 2);
  let response = await fetch(`${apiRoot}/releases/assets/${asset.id}`, { headers: { ...headers, Accept: 'application/octet-stream' },
    redirect: 'manual', signal: AbortSignal.timeout(60_000) });
  if (response.status >= 300 && response.status < 400) {
    const location = new URL(response.headers.get('location')); await response.body?.cancel();
    assert(location.protocol === 'https:' && ['release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(location.hostname));
    response = await fetch(location, { redirect: 'error', signal: AbortSignal.timeout(60_000) });
  }
  assert(response.ok && response.body, `Manifest download: HTTP ${response.status}`);
  const chunks = []; let size = 0;
  for await (const chunk of response.body) { size += chunk.length; assert(size <= asset.size); chunks.push(Buffer.from(chunk)); }
  const bytes = Buffer.concat(chunks); assert.equal(bytes.length, asset.size); assert.equal(hash(bytes), expected.sha256);
  return bytes;
}

const release = await api(`/releases/${descriptor.releaseId}`);
assert(release.draft === true && release.tag_name === descriptor.tag, 'Only the existing unpublished component draft may change');
const assets = await api(`/releases/${descriptor.releaseId}/assets?per_page=100`); assert(assets.length < 100);
function assetNamed(name) {
  const matches = assets.filter((asset) => asset.name === name); assert.equal(matches.length, 1, `Expected existing asset ${name}`); return matches[0];
}
const packages = [];
for (const expected of descriptor.manifests) {
  const manifest = JSON.parse(gunzipSync(await manifestBytes(assetNamed(`${expected.id}.manifest.json.gz`), expected), { maxOutputLength: 32 * 1024 ** 2 }));
  assert(manifest.id === expected.id && manifest.cloudVerification.allFilesMatchTestedRuntime
    && manifest.cloudVerification.verifiedFiles === manifest.files.length);
  const parts = manifest.parts.map((part) => {
    const asset = assetNamed(part.name);
    assert(asset.state === 'uploaded' && asset.size === part.bytes && asset.digest === `sha256:${part.sha256}`);
    return { ...part, url: `https://github.com/${repository}/releases/download/${descriptor.tag}/${part.name}` };
  });
  packages.push({ id: manifest.id, version: manifest.version, compatibility: manifest.compatibility,
    installedBytes: manifest.installedBytes, files: manifest.files, parts });
}
const payload = Buffer.from(JSON.stringify({ ...descriptor.header, packages }));
assert.equal(hash(payload), descriptor.catalogSha256, 'Catalog reconstruction must match the locally signed bytes');
const key = createPublicKey(descriptor.publicKey); assert.equal(key.asymmetricKeyType, 'ed25519');
assert(verify(null, payload, key, Buffer.from(descriptor.signature, 'base64')), 'Local public signature must verify');
const metadata = {
  'component-catalog.json': { schemaVersion: 1, keyId: descriptor.keyId, payload: payload.toString('base64'), signature: descriptor.signature },
  'component-trust.json': { [descriptor.keyId]: descriptor.publicKey },
};
for (const [name, content] of Object.entries(metadata)) {
  const bytes = Buffer.from(JSON.stringify(content, null, 2) + '\n');
  const expected = descriptor.metadata.find((item) => item.name === name);
  assert(expected && bytes.length === expected.bytes && hash(bytes) === expected.sha256);
  const existing = assets.find((asset) => asset.name === name);
  if (existing?.state === 'uploaded') {
    assert(existing.size === bytes.length && existing.digest === `sha256:${expected.sha256}`, 'Never replace complete differing metadata');
    process.stdout.write(JSON.stringify({ verifiedExisting: name }) + '\n'); continue;
  }
  if (existing) {
    assert(existing.state === 'starter' && existing.digest === null && existing.size === bytes.length, 'Preserve unexpected asset');
    await api(`/releases/assets/${existing.id}`, 'DELETE');
  }
  const uploadedResponse = await fetch(`https://uploads.github.com/repos/${repository}/releases/${descriptor.releaseId}/assets?name=${name}`, {
    method: 'POST', headers: { ...headers, 'Content-Type': 'application/octet-stream' }, body: bytes,
    redirect: 'error', signal: AbortSignal.timeout(120_000),
  });
  assert(uploadedResponse.ok, `Metadata upload: HTTP ${uploadedResponse.status}`);
  const uploaded = await uploadedResponse.json();
  assert(uploaded.name === name && uploaded.size === bytes.length && uploaded.state === 'uploaded' && uploaded.digest === `sha256:${expected.sha256}`);
  process.stdout.write(JSON.stringify({ uploadedIdenticalSignedMetadata: name, bytes: bytes.length }) + '\n');
}
process.stdout.write(JSON.stringify({ publicSignatureVerified: true, privateKeyAccessed: false, draft: true, audioGenerationStarted: false }) + '\n');
