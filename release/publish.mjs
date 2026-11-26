import { execFileSync } from 'node:child_process';
import { createDecipheriv, createHash, createHmac, createPublicKey, hkdfSync, verify } from 'node:crypto';
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const repo = 'Lathorian/musicdev-releases';
const installer = 'MusicDev-Setup-x64.exe';
const manifestName = 'musicdev-update.json';
const requestName = /^release-requests\/v((?:0|[1-9]\d{0,5})\.(?:0|[1-9]\d{0,5})\.(?:0|[1-9]\d{0,5}))\.json$/;
const maxInstaller = 256 * 1024 * 1024;
const compare = (a, b) => {
  const left = a.split('.').map(Number), right = b.split('.').map(Number);
  return left[0] - right[0] || left[1] - right[1] || left[2] - right[2];
};

function ensure(condition, message) {
  if (!condition) throw new Error(message);
}

function run(command, ...args) {
  return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
}

function api(endpoint, ...args) {
  const response = run('gh', 'api', 'repos/' + repo + endpoint, ...args);
  return response ? JSON.parse(response) : null;
}

function inspectRequest(path, trusted) {
  const match = requestName.exec(path);
  ensure(match, 'Expected a versioned release-requests JSON file.');
  const version = match[1];
  const request = JSON.parse(readFileSync(path, 'utf8'));
  const envelope = request.manifest;
  ensure(trusted.repository === repo && typeof trusted.public_key === 'string', 'Release key configuration is invalid.');
  const key = Buffer.from(trusted.public_key, 'base64');
  const signed = Buffer.from(envelope.signed, 'base64');
  const signature = Buffer.from(envelope.signature, 'base64');
  ensure(key.length === 32 && signature.length === 64 && signed.length < 2048, 'Signed manifest has an invalid format.');
  const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), key]);
  ensure(verify(null, signed, createPublicKey({ key: spki, format: 'der', type: 'spki' }), signature),
    'Publisher signature is invalid.');
  const metadata = JSON.parse(signed.toString('utf8'));
  ensure(metadata.repository === repo && metadata.product === 'MusicDev' && metadata.platform === 'windows-x64' &&
    metadata.version === version && metadata.asset === installer && /^[a-f0-9]{64}$/.test(metadata.sha256) &&
    Number.isSafeInteger(metadata.size) && metadata.size > 0 && metadata.size <= maxInstaller,
  'Signed metadata does not match this release.');
  const link = /^https:\/\/send\.vis\.ee\/download\/([a-f0-9]{16})\/?#([A-Za-z0-9_-]{22})$/.exec(request.installer_url);
  ensure(link, 'Expected a share URL for the installer on send.vis.ee.');
  ensure(typeof request.notes === 'string' && request.notes.length > 0 && request.notes.length <= 8000,
    'Release notes are required (up to 8,000 characters).');
  return { version, envelope, metadata, link, notes: request.notes };
}

const derive = (secret, salt, info, length) => Buffer.from(hkdfSync('sha256', secret, salt, info, length));

function decryptRecord(record, key, nonce) {
  ensure(record.length >= 17, 'Installer share has a truncated record.');
  const decipher = createDecipheriv('aes-128-gcm', key, nonce);
  decipher.setAuthTag(record.subarray(-16));
  return Buffer.concat([decipher.update(record.subarray(0, -16)), decipher.final()]);
}

async function download(candidate, destination) {
  const { link, metadata } = candidate;
  const secret = Buffer.from(link[2], 'base64url');
  const auth = derive(secret, Buffer.alloc(0), 'authentication', 64);
  const endpoint = 'https://send.vis.ee/api/download/blob/' + link[1];
  const request = (nonce) => fetch(endpoint, {
    headers: { Authorization: 'send-v1 ' + createHmac('sha256', auth).update(Buffer.from(nonce, 'base64url')).digest('base64url') },
    redirect: 'error',
    signal: AbortSignal.timeout(180_000),
  });
  let response = await request('yRCdyQ1EMSA3mo4rqSkuNQ==');
  if (response.status === 401) {
    const challenge = /^send-v1 ([A-Za-z0-9_+/=-]+)$/i.exec(response.headers.get('www-authenticate') ?? '');
    ensure(challenge, 'Installer share returned an invalid authentication challenge.');
    await response.body?.cancel();
    response = await request(challenge[1]);
  }
  ensure(response.ok && response.body, 'Installer share download returned HTTP ' + response.status + '.');
  // Send v3 uses AES-128-GCM records with a 21-byte stream header.
  const parts = [];
  let buffered = 0;
  for await (const part of response.body) {
    buffered += part.length;
    ensure(buffered <= metadata.size + Math.ceil(metadata.size / (65536 - 17)) * 17 + 21,
      'Installer share exceeded the signed size.');
    parts.push(part);
  }
  const encrypted = Buffer.concat(parts, buffered);
  ensure(encrypted.length > 37 && encrypted[20] === 0 && encrypted.readUInt32BE(16) === 65536,
    'Installer share has an invalid stream header.');
  const salt = encrypted.subarray(0, 16);
  const key = derive(secret, salt, 'Content-Encoding: aes128gcm\0', 16);
  const nonce = derive(secret, salt, 'Content-Encoding: nonce\0', 12);
  const digest = createHash('sha256');
  let size = 0;
  const out = openSync(destination, 'wx');
  try {
    for (let offset = 21, sequence = 0; offset < encrypted.length; offset += 65536, sequence++) {
      const seqNonce = Buffer.from(nonce);
      seqNonce.writeUInt32BE((nonce.readUInt32BE(8) ^ sequence) >>> 0, 8);
      const record = decryptRecord(encrypted.subarray(offset, offset + 65536), key, seqNonce);
      let marker = record.length - 1;
      while (marker >= 0 && record[marker] === 0) marker--;
      const final = offset + 65536 >= encrypted.length;
      ensure(record[marker] === (final ? 2 : 1), 'Installer share has an invalid record terminator.');
      const data = record.subarray(0, marker);
      size += data.length;
      ensure(size <= metadata.size, 'Installer exceeded the signed size.');
      if (sequence === 0) ensure(data.subarray(0, 2).equals(Buffer.from('MZ')), 'Expected a Windows executable.');
      digest.update(data);
      writeSync(out, data);
    }
  } finally {
    closeSync(out);
  }
  ensure(size === metadata.size && digest.digest('hex') === metadata.sha256,
    'The installer does not match the publisher-signed size and SHA-256.');
}

function checkedAssets(id, expected) {
  const uploaded = new Map();
  for (const asset of api('/releases/' + id + '/assets')) {
    ensure(expected.has(asset.name), 'Unexpected asset on this release: ' + asset.name);
    ensure(asset.state === 'uploaded' && asset.digest === 'sha256:' + expected.get(asset.name),
      'Asset ' + asset.name + ' already exists with different bytes or is incomplete. Review the draft.');
    uploaded.set(asset.name, asset);
  }
  return uploaded;
}

function releases() {
  return api('/releases?per_page=100', '--paginate', '--slurp').flat();
}

async function publish(path, verifyOnly = false) {
  const trust = JSON.parse(readFileSync('release/update-config.json', 'utf8'));
  const data = inspectRequest(path, trust);
  const version = data.version, tag = 'v' + version;
  const manifestBytes = Buffer.from(JSON.stringify(data.envelope, null, 2) + '\n');
  const expected = new Map([
    [installer, data.metadata.sha256],
    [manifestName, createHash('sha256').update(manifestBytes).digest('hex')],
  ]);
  let found;
  if (!verifyOnly) {
    const all = releases();
    found = all.find((release) => release.tag_name === tag);
    if (found && !found.draft) {
      ensure(checkedAssets(found.id, expected).size === expected.size, 'Published release is missing an asset.');
      console.log('The same signed release is already published.', found.html_url);
      return;
    }
    ensure(!all.some((release) => !release.draft && !release.prerelease &&
      requestName.test('release-requests/' + release.tag_name + '.json') &&
      compare(release.tag_name.slice(1), version) > 0), 'A newer stable version is already public.');
  }

  const dir = mkdtempSync(join(tmpdir(), 'musicdev-release-'));
  try {
    const file = join(dir, installer);
    await download(data, file);
    console.log('Verified signed Windows installer for ' + tag + '.');
    if (verifyOnly) return;

    const manifest = join(dir, manifestName);
    writeFileSync(manifest, manifestBytes);
    if (found) {
      ensure(!found.prerelease, 'This draft is marked as a prerelease.');
    } else {
      const notes = join(dir, 'notes.md');
      writeFileSync(notes, data.notes);
      run('gh', 'release', 'create', tag, '--repo', repo, '--title', 'MusicDev ' + version,
        '--notes-file', notes, '--draft');
      found = releases().find((release) => release.tag_name === tag);
      ensure(found?.draft, 'The release draft could not be found.');
    }
    const existing = checkedAssets(found.id, expected);
    for (const [name, pathname] of [[manifestName, manifest], [installer, file]]) {
      if (!existing.has(name)) run('gh', 'release', 'upload', tag, pathname, '--repo', repo);
    }
    ensure(checkedAssets(found.id, expected).size === expected.size, 'The draft is missing a signed release asset.');
    const published = api('/releases/' + found.id, '--method', 'PATCH', '-F', 'draft=false', '-f', 'make_latest=true');
    ensure(published && !published.draft && published.tag_name === tag, 'GitHub did not publish the release.');
    console.log(published.html_url);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function requestedFile(event) {
  if (process.env.GITHUB_EVENT_NAME === 'workflow_dispatch') {
    return 'release-requests/v' + (event.inputs?.version ?? '') + '.json';
  }
  ensure(/^[a-f0-9]{40}$/.test(event.before ?? '') && /^[a-f0-9]{40}$/.test(event.after ?? ''),
    'Invalid release request event.');
  const changed = run('git', 'diff', '--name-only', '--diff-filter=AM', event.before, event.after, '--', 'release-requests');
  const paths = changed.split('\n').filter((path) => requestName.test(path));
  ensure(paths.length === 1, 'Commit one versioned release request per push.');
  return paths[0];
}

const args = process.argv.slice(2);
if (args[0] === '--verify' && args[1] && args.length === 2) {
  await publish(args[1], true);
} else {
  ensure(args.length === 0 && process.env.GITHUB_REPOSITORY === repo && process.env.GITHUB_REF === 'refs/heads/main',
    'Run publishing from the dedicated release repository’s main branch.');
  const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  await publish(requestedFile(event));
}
