'use strict';

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

let child = null;
let active = null;

function assetName(arch = process.arch) {
  if (arch === 'x64') return 'cloudflared-linux-amd64';
  if (arch === 'arm64') return 'cloudflared-linux-arm64';
  return '';
}

function binaryPath() {
  const home = process.env.HOME || '/tmp';
  return path.join(home, '.infrlo-node', 'bin', 'cloudflared');
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

async function ensureBinary() {
  const file = binaryPath();
  try {
    fs.accessSync(file, fs.constants.X_OK);
    return file;
  } catch {}

  const asset = assetName();
  if (!asset) throw new Error(`unsupported_arch_${process.arch}`);

  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/${asset}`;

  console.log(`CF_TUNNEL_DOWNLOAD_START arch=${process.arch}`);
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 45000);
  try {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: { 'user-agent': 'infrlo-node/1.1.0' },
      signal: ctl.signal
    });
    if (!res.ok) throw new Error(`download_http_${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length < 5 * 1024 * 1024) throw new Error(`download_too_small_${buf.length}`);
    fs.writeFileSync(tmp, buf, { mode: 0o700 });
    fs.renameSync(tmp, file);
    fs.chmodSync(file, 0o700);
    console.log(`CF_TUNNEL_DOWNLOAD_READY bytes=${buf.length}`);
    return file;
  } finally {
    clearTimeout(timer);
    try { fs.unlinkSync(tmp); } catch {}
  }
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
    env: process.env
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

module.exports = { ensureBinary, parseRegistered, startQuickTunnel, stopQuickTunnel };
