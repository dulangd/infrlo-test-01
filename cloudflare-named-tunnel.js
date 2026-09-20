'use strict';

const { spawn } = require('child_process');
const { ensureBinary, cloudflaredEnv, parseRegistered } = require('./cloudflare-quick-tunnel.js');

let child = null;
let active = null;

function waitForRegistration(proc, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let lastIssue = '';

    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      err ? reject(err) : resolve(value);
    };

    const scan = chunk => {
      if (settled) return;
      const text = String(chunk || '');
      const reg = parseRegistered(text);
      if (reg) {
        console.log(`CF_NAMED_TUNNEL_EDGE_REGISTERED protocol=${reg.protocol} location=${reg.location}`);
        return finish(null, reg);
      }
      if (/7844/.test(text) && /(fail|timeout|blocked|unreachable|refused)/i.test(text)) lastIssue = 'port-7844';
      else if (/failed to dial|connection timeout|connect timeout/i.test(text)) lastIssue = 'edge-dial';
      else if (/DNS/i.test(text) && /(fail|unresolv|error)/i.test(text)) lastIssue = 'edge-dns';
    };

    proc.stdout.on('data', scan);
    proc.stderr.on('data', scan);
    proc.once('error', err => finish(err));
    proc.once('exit', code => {
      if (!settled) finish(new Error(`cloudflared_named_exit_${code}_${lastIssue || 'before-register'}`));
    });

    const timer = setTimeout(() => finish(new Error(`cloudflared_named_timeout_${lastIssue || 'before-register'}`)), timeoutMs);
  });
}

async function startNamedTunnel(token, hostname) {
  if (active && child && child.exitCode == null && !child.killed) return active;

  const tunnelToken = String(token || '').trim();
  const publicHost = String(hostname || '').trim().toLowerCase();
  if (!tunnelToken) throw new Error('missing_tunnel_token');
  if (!publicHost || !publicHost.includes('.')) throw new Error('invalid_tunnel_hostname');

  const binary = await ensureBinary();
  console.log(`CF_NAMED_TUNNEL_START host=${publicHost} protocol=auto`);

  child = spawn(binary, [
    'tunnel',
    '--no-autoupdate',
    'run',
    '--token', tunnelToken
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: cloudflaredEnv()
  });

  const registered = await waitForRegistration(child);
  active = {
    host: publicHost,
    port: 443,
    tls: true,
    edgeProtocol: registered.protocol,
    edgeLocation: registered.location
  };

  console.log(`CF_NAMED_TUNNEL_READY host=${publicHost} protocol=${registered.protocol} location=${registered.location}`);

  child.once('exit', code => {
    if (active) console.log(`CF_NAMED_TUNNEL_EXIT code=${code}`);
    active = null;
    child = null;
  });

  return active;
}

function stopNamedTunnel() {
  const proc = child;
  child = null;
  active = null;
  if (proc && proc.exitCode == null) {
    try { proc.kill('SIGTERM'); } catch {}
  }
}

module.exports = { startNamedTunnel, stopNamedTunnel };
