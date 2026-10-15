'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { Readable } = require('stream');
const { finished } = require('stream/promises');
const { spawn } = require('child_process');
const tls = require('tls');

let child = null;
let active = null;

function assetName(arch = process.arch) {
  if (arch === 'x64') return 'cloudflared-linux-amd64';
  if (arch === 'arm64') return 'cloudflared-linux-arm64';
  return '';
}

function homeDir() {
  return process.env.HOME || os.tmpdir() || '/tmp';
}

function stateDir() {
  return path.join(homeDir(), '.infrlo-node');
}

function caBundlePath() {
  return path.join(stateDir(), 'ca-bundle.pem');
}

function executable(file) {
  if (!file) return false;
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function pathCandidates() {
  const out = [];
  const add = value => {
    const file = String(value || '').trim();
    if (file && !out.includes(file)) out.push(file);
  };

  add(process.env.CLOUDFLARED_BIN);
  for (const dir of String(process.env.PATH || '').split(path.delimiter)) {
    if (dir) add(path.join(dir, 'cloudflared'));
  }
  add('/usr/local/bin/cloudflared');
  add('/usr/bin/cloudflared');
  add('/bin/cloudflared');
  add(path.join(stateDir(), 'bin', 'cloudflared'));
  add(path.join(os.tmpdir() || '/tmp', 'infrlo-cloudflared', 'cloudflared'));
  return out;
}

function existingBinary() {
  for (const file of pathCandidates()) {
    if (executable(file)) {
      console.log(`CF_TUNNEL_BINARY_REUSE path=${file}`);
      return file;
    }
  }
  return '';
}

function nearestExistingDir(input) {
  let dir = path.resolve(input);
  while (dir !== path.dirname(dir)) {
    try {
      if (fs.statSync(dir).isDirectory()) return dir;
    } catch {}
    dir = path.dirname(dir);
  }
  return dir;
}

function freeBytes(input) {
  try {
    const stat = fs.statfsSync(nearestExistingDir(input));
    return Number(stat.bavail) * Number(stat.bsize);
  } catch {
    return -1;
  }
}

function formatMiB(bytes) {
  return bytes < 0 ? 'unknown' : (bytes / 1024 / 1024).toFixed(1);
}

function removeSafe(file) {
  try {
    fs.rmSync(file, { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
}

function cleanupRuntimeCaches() {
  const home = homeDir();
  const targets = [
    path.join(home, '.npm', '_cacache'),
    path.join(home, '.npm', '_logs'),
    path.join(home, '.cache', 'node-gyp'),
    path.join(os.tmpdir() || '/tmp', 'infrlo-cloudflared')
  ];

  let removed = 0;
  for (const target of targets) {
    try {
      if (!fs.existsSync(target)) continue;
      if (removeSafe(target)) removed += 1;
    } catch {}
  }

  const binDir = path.join(stateDir(), 'bin');
  try {
    for (const name of fs.readdirSync(binDir)) {
      if (/^cloudflared\..+\.tmp$/.test(name) && removeSafe(path.join(binDir, name))) removed += 1;
    }
  } catch {}

  console.log(`CF_STORAGE_CLEANUP targets_removed=${removed}`);
}

function downloadDirs() {
  const dirs = [
    path.join(stateDir(), 'bin'),
    path.join(os.tmpdir() || '/tmp', 'infrlo-cloudflared')
  ];
  return [...new Set(dirs)].sort((a, b) => freeBytes(b) - freeBytes(a));
}

function systemCaBundle() {
  const candidates = [
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/tls/certs/ca-bundle.crt',
    '/etc/ssl/cert.pem'
  ];
  for (const file of candidates) {
    try {
      fs.accessSync(file, fs.constants.R_OK);
      return file;
    } catch {}
  }
  return '';
}

function ensureCaBundle() {
  const system = systemCaBundle();
  if (system) return system;

  const file = caBundlePath();
  const roots = Array.isArray(tls.rootCertificates) ? tls.rootCertificates.filter(Boolean) : [];
  if (!roots.length) throw new Error('node_root_ca_empty');
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const body = roots.join('\n') + '\n';
  fs.writeFileSync(file, body, { mode: 0o600 });
  console.log(`CF_CA_BUNDLE_READY certificates=${roots.length}`);
  return file;
}

function cloudflaredEnv() {
  const caFile = ensureCaBundle();
  return {
    ...process.env,
    SSL_CERT_FILE: caFile
  };
}

function extractQuickTunnelUrl(text) {
  const matches = String(text || '').match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com\b/ig) || [];
  for (const value of matches) {
    try {
      const host = new URL(value).hostname.toLowerCase();
      if (host === 'api.trycloudflare.com') continue;
      if (!host.endsWith('.trycloudflare.com')) continue;
      return value;
    } catch {}
  }
  return '';
}

function sanitizeDiagnostic(text) {
  return String(text || '')
    .replace(/(--token\s+)[^\s]+/ig, '$1[REDACTED]')
    .replace(/(token[=:]\s*)[^\s]+/ig, '$1[REDACTED]')
    .replace(/[\r\n]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 420);
}

function parseRegistered(text) {
  const line = String(text || '');
  if (!/Registered tunnel connection/i.test(line)) return null;
  const protocol = (line.match(/protocol=([a-z0-9_-]+)/i) || [])[1] || 'unknown';
  const location = (line.match(/location=([a-z0-9_-]+)/i) || [])[1] || 'unknown';
  return { protocol, location };
}

async function downloadBinaryTo(dir, asset) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, 'cloudflared');
  const tmp = `${file}.${process.pid}.tmp`;
  const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/${asset}`;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 60000);

  console.log(`CF_TUNNEL_DOWNLOAD_START arch=${process.arch} dir=${dir} free_mib=${formatMiB(freeBytes(dir))}`);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: { 'user-agent': 'infrlo-node/1.3.3' },
      signal: ctl.signal
    });
    if (!res.ok) throw new Error(`download_http_${res.status}`);
    if (!res.body) throw new Error('download_empty_body');

    const output = fs.createWriteStream(tmp, { mode: 0o700, flags: 'w' });
    await finished(Readable.fromWeb(res.body).pipe(output));

    const size = fs.statSync(tmp).size;
    if (size < 5 * 1024 * 1024) throw new Error(`download_too_small_${size}`);
    fs.renameSync(tmp, file);
    fs.chmodSync(file, 0o700);
    console.log(`CF_TUNNEL_DOWNLOAD_READY bytes=${size} path=${file}`);
    return file;
  } finally {
    clearTimeout(timer);
    try { fs.unlinkSync(tmp); } catch {}
  }
}

async function ensureBinary() {
  const reused = existingBinary();
  if (reused) return reused;

  const asset = assetName();
  if (!asset) throw new Error(`unsupported_arch_${process.arch}`);

  let dirs = downloadDirs();
  console.log('CF_STORAGE_DIAG ' + dirs.map(dir => `${dir}=${formatMiB(freeBytes(dir))}MiB`).join(' '));

  const minimumFree = 64 * 1024 * 1024;
  if (dirs.every(dir => {
    const free = freeBytes(dir);
    return free >= 0 && free < minimumFree;
  })) {
    cleanupRuntimeCaches();
    dirs = downloadDirs();
    console.log('CF_STORAGE_AFTER_CLEANUP ' + dirs.map(dir => `${dir}=${formatMiB(freeBytes(dir))}MiB`).join(' '));
  }

  const errors = [];
  for (const dir of dirs) {
    try {
      return await downloadBinaryTo(dir, asset);
    } catch (e) {
      const code = String(e?.code || '');
      errors.push(`${dir}:${code || e.message}`);
      if (code === 'ENOSPC' || /no space left on device|ENOSPC/i.test(String(e?.message || e))) {
        cleanupRuntimeCaches();
        console.warn(`CF_TUNNEL_STORAGE_RETRY dir=${dir} free_mib=${formatMiB(freeBytes(dir))}`);
        continue;
      }
      throw e;
    }
  }

  throw new Error('cloudflared_storage_exhausted_' + errors.join('|'));
}

function waitForReady(proc, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let url = '';
    let registered = null;
    let lastIssue = '';
    let lastDiagnostic = '';

    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      err ? reject(err) : resolve(value);
    };

    const maybeReady = () => {
      if (url && registered) finish(null, { url, ...registered });
    };

    const scan = chunk => {
      if (settled) return;
      const text = String(chunk || '');

      if (!url) {
        const found = extractQuickTunnelUrl(text);
        if (found) {
          url = found;
          console.log(`CF_QUICK_TUNNEL_URL_ASSIGNED host=${new URL(url).hostname.toLowerCase()}`);
        }
      }

      if (!registered) {
        const reg = parseRegistered(text);
        if (reg) {
          registered = reg;
          console.log(`CF_QUICK_TUNNEL_EDGE_REGISTERED protocol=${reg.protocol} location=${reg.location}`);
        }
      }

      if (/7844/.test(text) && /(fail|timeout|blocked|unreachable|refused)/i.test(text)) lastIssue = 'port-7844';
      else if (/failed to dial|connection timeout|connect timeout/i.test(text)) lastIssue = 'edge-dial';
      else if (/DNS/i.test(text) && /(fail|unresolv|error)/i.test(text)) lastIssue = 'edge-dns';
      else if (/failed to request quick tunnel|quick tunnel.*(fail|error)|trycloudflare.*(fail|error)|status code/i.test(text)) lastIssue = 'quick-tunnel-api';

      for (const line of text.split(/\r?\n/)) {
        if (!line.trim()) continue;
        if (/\b(ERR|WRN)\b|error=|failed|failure|forbidden|unauthorized|rate.?limit|timeout|refused/i.test(line)) {
          const diag = sanitizeDiagnostic(line);
          if (diag && diag !== lastDiagnostic) {
            lastDiagnostic = diag;
            console.log(`CF_TUNNEL_DIAG ${diag}`);
          }
        }
      }

      maybeReady();
    };

    proc.stdout.on('data', scan);
    proc.stderr.on('data', scan);
    proc.once('error', err => finish(err));
    proc.once('exit', code => {
      if (!settled) finish(new Error(`cloudflared_exit_${code}_${lastIssue || 'before-register'}`));
    });

    const timer = setTimeout(() => {
      finish(new Error(`cloudflared_edge_timeout_${lastIssue || (url ? 'url-only' : 'no-url')}`));
    }, timeoutMs);
  });
}

async function startQuickTunnel(localPort) {
  if (active && child && child.exitCode == null && !child.killed) return active;
  const port = Number(localPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid_local_port');

  const binary = await ensureBinary();
  console.log(`CF_QUICK_TUNNEL_START origin=http://127.0.0.1:${port} protocol=auto`);

  child = spawn(binary, [
    'tunnel',
    '--no-autoupdate',
    '--url', `http://127.0.0.1:${port}`
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: cloudflaredEnv()
  });

  const ready = await waitForReady(child);
  const host = new URL(ready.url).hostname.toLowerCase();
  active = {
    url: ready.url,
    host,
    port: 443,
    tls: true,
    edgeProtocol: ready.protocol,
    edgeLocation: ready.location
  };

  console.log(`CF_QUICK_TUNNEL_READY host=${host} protocol=${ready.protocol} location=${ready.location}`);

  child.once('exit', code => {
    if (active) console.log(`CF_QUICK_TUNNEL_EXIT code=${code}`);
    active = null;
    child = null;
  });

  return active;
}

function stopQuickTunnel() {
  const proc = child;
  child = null;
  active = null;
  if (proc && proc.exitCode == null) {
    try { proc.kill('SIGTERM'); } catch {}
  }
}

module.exports = { ensureBinary, ensureCaBundle, cloudflaredEnv, parseRegistered, startQuickTunnel, stopQuickTunnel };
