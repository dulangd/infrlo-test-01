'use strict';

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const net = require('net');
const crypto = require('crypto');

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function enabled(v) { return /^(1|true|yes|on)$/i.test(String(v || '')); }

function buildVlessRequest(uuid, host, port, payload) {
  const id = Buffer.from(uuid.replace(/-/g, ''), 'hex');
  const domain = Buffer.from(host, 'utf8');
  const head = Buffer.alloc(1 + 16 + 1 + 1 + 2 + 1 + 1 + domain.length);
  let i = 0;
  head[i++] = 0;
  id.copy(head, i); i += 16;
  head[i++] = 0;
  head[i++] = 1;
  head.writeUInt16BE(port, i); i += 2;
  head[i++] = 2;
  head[i++] = domain.length;
  domain.copy(head, i);
  return Buffer.concat([head, Buffer.from(payload, 'utf8')]);
}

function maskedClientFrame(payload) {
  payload = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const mask = crypto.randomBytes(4);
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x82, 0x80 | payload.length]);
  } else if (payload.length <= 0xffff) {
    header = Buffer.alloc(4);
    header[0] = 0x82;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    throw new Error('selftest_packet_too_large');
  }
  const out = Buffer.from(payload);
  for (let i = 0; i < out.length; i++) out[i] ^= mask[i & 3];
  return Buffer.concat([header, mask, out]);
}

function parseServerFrames(buffer) {
  const payloads = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const b0 = buffer[offset];
    const b1 = buffer[offset + 1];
    const opcode = b0 & 0x0f;
    let len = b1 & 0x7f;
    let h = 2;
    if (b1 & 0x80) throw new Error('masked_server_frame');
    if (len === 126) {
      if (offset + 4 > buffer.length) break;
      len = buffer.readUInt16BE(offset + 2);
      h = 4;
    } else if (len === 127) {
      if (offset + 10 > buffer.length) break;
      const big = buffer.readBigUInt64BE(offset + 2);
      if (big > 1048576n) throw new Error('oversize_server_frame');
      len = Number(big);
      h = 10;
    }
    if (offset + h + len > buffer.length) break;
    const payload = buffer.subarray(offset + h, offset + h + len);
    offset += h + len;
    if (opcode === 2 || opcode === 0) payloads.push(Buffer.from(payload));
    if (opcode === 8) return { payloads, rest: buffer.subarray(offset), closed: true };
  }
  return { payloads, rest: buffer.subarray(offset), closed: false };
}

function runWsVlessAttempt({ socketFactory, connectedEvent, initialStage, hostHeader, identity, timeoutMs = 12000 }) {
  return new Promise(resolve => {
    let settled = false;
    let phase = initialStage;
    let raw = Buffer.alloc(0);
    let wsBuf = Buffer.alloc(0);
    let app = Buffer.alloc(0);
    let ack = false;
    let socket;

    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { socket?.destroy(); } catch {}
      resolve({ ...result, ack });
    };

    const timer = setTimeout(
      () => finish({ ok: false, stage: phase === 'relay' ? 'relay-timeout' : `${phase}-timeout` }),
      timeoutMs
    );

    const key = crypto.randomBytes(16).toString('base64');
    const expectedAccept = crypto.createHash('sha1')
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');

    socket = socketFactory();
    socket.once(connectedEvent, () => {
      phase = 'upgrade';
      socket.write([
        `GET ${identity.wsPath} HTTP/1.1`,
        `Host: ${hostHeader}`,
        'Upgrade: websocket',
        'Connection: Upgrade',
        `Sec-WebSocket-Key: ${key}`,
        'Sec-WebSocket-Version: 13',
        '', ''
      ].join('\r\n'));
    });

    socket.on('data', chunk => {
      if (phase === 'upgrade') {
        raw = Buffer.concat([raw, chunk]);
        const end = raw.indexOf('\r\n\r\n');
        if (end < 0) return;
        const head = raw.subarray(0, end).toString('latin1');
        const rest = raw.subarray(end + 4);
        const match = head.match(/^HTTP\/1\.[01]\s+(\d{3})/i);
        const status = match ? Number(match[1]) : 0;
        if (status !== 101) return finish({ ok: false, stage: 'upgrade', status });
        const accept = (head.match(/^Sec-WebSocket-Accept:\s*(.+)$/im) || [])[1]?.trim();
        if (accept !== expectedAccept) return finish({ ok: false, stage: 'upgrade-accept' });

        phase = 'relay';
        const targetHost = 'example.com';
        const request = 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n';
        socket.write(maskedClientFrame(buildVlessRequest(identity.uuid, targetHost, 80, request)));
        wsBuf = rest;
      } else if (phase === 'relay') {
        wsBuf = Buffer.concat([wsBuf, chunk]);
      }

      if (phase === 'relay' && wsBuf.length) {
        try {
          const parsed = parseServerFrames(wsBuf);
          wsBuf = parsed.rest;
          if (parsed.payloads.length) app = Buffer.concat([app, ...parsed.payloads]);
          if (app.length >= 2 && app[0] === 0 && app[1] === 0) ack = true;
          const text = app.length > 2 ? app.subarray(2).toString('latin1') : '';
          if (/HTTP\/1\.[01]\s+\d{3}\b/.test(text)) {
            return finish({ ok: true, stage: 'relay', target: 'example.com:80' });
          }
          if (parsed.closed) return finish({ ok: false, stage: 'relay-closed' });
        } catch {
          return finish({ ok: false, stage: 'frame-parse' });
        }
      }
    });

    socket.once('error', err => {
      const code = String(err?.code || 'ERR').replace(/[^A-Z0-9_-]/gi, '');
      finish({ ok: false, stage: phase, code });
    });
  });
}

function localAttempt(identity) {
  const port = Number(process.env.PORT || 5000);
  return runWsVlessAttempt({
    socketFactory: () => net.connect({ host: '127.0.0.1', port }),
    connectedEvent: 'connect',
    initialStage: 'local-connect',
    hostHeader: `localhost:${port}`,
    identity
  });
}

function publicAttempt(host, port, identity, connectHost = '') {
  return runWsVlessAttempt({
    socketFactory: () => tls.connect({
      host: connectHost || host,
      port,
      servername: host,
      ALPNProtocols: ['http/1.1'],
      rejectUnauthorized: true
    }),
    connectedEvent: 'secureConnect',
    initialStage: 'tls',
    hostHeader: port === 443 ? host : `${host}:${port}`,
    identity
  });
}

async function resolveIpv4ViaDoh(host) {
  const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`;
  const res = await fetch(url, {
    headers: { accept: 'application/dns-json', 'user-agent': 'infrlo-node/1.2.0' },
    signal: AbortSignal.timeout(5000)
  });
  if (!res.ok) throw new Error(`doh_http_${res.status}`);
  const body = await res.json();
  if (Number(body.Status) !== 0) return [];
  return (Array.isArray(body.Answer) ? body.Answer : [])
    .filter(x => Number(x.type) === 1 && net.isIP(String(x.data || '').trim()) === 4)
    .map(x => String(x.data).trim());
}

async function waitForIpv4(host, attempts = 20) {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const ips = await resolveIpv4ViaDoh(host);
      if (ips.length) {
        console.log(`CF_TUNNEL_DNS_READY attempt=${attempt} host=${host} ip=${ips[0]}`);
        return ips[0];
      }
      if ([1,4,8,12,16,20].includes(attempt)) {
        console.log(`CF_TUNNEL_DNS_WAIT attempt=${attempt} host=${host} reason=no-a-record`);
      }
    } catch (e) {
      if ([1,4,8,12,16,20].includes(attempt)) {
        const code = String(e?.message || e || 'ERR').replace(/\s+/g, '_').slice(0, 80);
        console.log(`CF_TUNNEL_DNS_WAIT attempt=${attempt} host=${host} reason=${code}`);
      }
    }
    if (attempt < attempts) await sleep(1000);
  }
  return '';
}

function stateFile() {
  const dir = path.resolve(process.env.STATE_DIR || path.join(__dirname, '.state'));
  return path.join(dir, 'identity.json');
}

function saveResult(result) {
  try {
    const dir = path.resolve(process.env.STATE_DIR || path.join(__dirname, '.state'));
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'public-selftest.json'),
      JSON.stringify({ ...result, checked_at: new Date().toISOString() }, null, 2) + '\n',
      { mode: 0o600 }
    );
  } catch {}
}

async function testPublicEndpoint(label, host, identity, attempts = 3) {
  const publicHost = String(host || '').trim().toLowerCase();
  if (!publicHost) {
    return { ok: false, stage: 'configuration', label, host: '' };
  }

  const connectHost = await waitForIpv4(publicHost, 20);
  if (!connectHost) {
    return { ok: false, stage: 'dns-not-ready', label, host: publicHost, port: 443, tls: true };
  }

  let result = { ok: false, stage: 'not-run' };
  for (let attempt = 1; attempt <= attempts; attempt++) {
    result = await publicAttempt(publicHost, 443, identity, connectHost);
    result = { ...result, attempt, label, host: publicHost, port: 443, tls: true };
    if (result.ok) break;
    if (attempt < attempts) await sleep(3000);
  }
  return result;
}

function resultDetail(result) {
  return [
    `stage=${result?.stage || 'failed'}`,
    result?.status ? `status=${result.status}` : '',
    result?.code ? `code=${result.code}` : '',
    result?.ack ? 'ack=true' : ''
  ].filter(Boolean).join(' ');
}

async function run() {
  const file = stateFile();
  for (let i = 0; i < 40 && !fs.existsSync(file); i++) await sleep(250);
  if (!fs.existsSync(file)) {
    console.log('PUBLIC_WS_SELFTEST_FAILED stage=identity');
    return;
  }

  let identity;
  try { identity = JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch {
    console.log('PUBLIC_WS_SELFTEST_FAILED stage=identity');
    return;
  }

  const api = require('./index.js');

  const local = await localAttempt(identity);
  console.log(local.ok
    ? `LOCAL_VLESS_SELFTEST_READY target=${local.target}`
    : `LOCAL_VLESS_SELFTEST_FAILED stage=${local.stage}${local.ack ? ' ack=true' : ''}`);

  if (!local.ok) {
    saveResult({ ok: false, logical_nodes: 1, local, native: { ok: false, stage: 'not-run' }, cloudflare: { ok: false, stage: 'not-run' } });
    return;
  }

  const nativeHost = String(process.env.INFRLO_NATIVE_HOST || 'qqnioc.infrlo.com').trim().toLowerCase();
  let nativeResult = { ok: false, stage: 'not-run', host: nativeHost, port: 443, tls: true };

  if (nativeHost) {
    nativeResult = await testPublicEndpoint('native', nativeHost, identity, 3);
    api.setIngressSelfTest('native', nativeResult);
    if (nativeResult.ok) {
      api.setIngressEndpoint('native', {
        host: nativeHost,
        port: 443,
        tls: true,
        mode: 'infrlo-native'
      }, 'native-selftest');
      console.log(`NATIVE_WS_SELFTEST_READY target=${nativeResult.target} endpoint=${nativeHost}:443 tls=on mode=infrlo-native`);
      const nativeSub = api.getSubscriptionUrl('native', true);
      if (nativeSub) console.log(`SUB_NATIVE_READY ${nativeSub}`);
    } else {
      console.log(`NATIVE_WS_SELFTEST_FAILED ${resultDetail(nativeResult)} endpoint=${nativeHost}:443`);
    }
  } else {
    api.setIngressSelfTest('native', { ok: false, stage: 'configuration' });
    console.log('NATIVE_WS_SELFTEST_SKIPPED reason=native-host-missing');
  }

  const token = String(process.env.CF_TUNNEL_TOKEN || '').trim();
  const configuredCfHost = String(process.env.CF_TUNNEL_HOSTNAME || '').trim().toLowerCase();
  const named = !!(token && configuredCfHost);
  const quick = enabled(process.env.INFRLO_CF_QUICK_TUNNEL);

  let cloudflareResult = { ok: false, stage: 'not-run', host: configuredCfHost, port: 443, tls: true };
  let cloudflareHost = configuredCfHost;
  let cloudflareMode = named ? 'cloudflare-named-tunnel' : (quick ? 'cloudflare-quick-tunnel' : 'cloudflare-disabled');

  if (named || quick) {
    let tunnel = null;
    try {
      if (named) {
        tunnel = await require('./cloudflare-named-tunnel.js').startNamedTunnel(token, configuredCfHost);
      } else {
        tunnel = await require('./cloudflare-quick-tunnel.js').startQuickTunnel(Number(process.env.PORT || 5000));
      }
      cloudflareHost = tunnel.host;
      cloudflareResult = await testPublicEndpoint('cloudflare', cloudflareHost, identity, 3);
    } catch (e) {
      const code = String(e?.message || e || 'ERR').replace(/\s+/g, '_').slice(0, 100);
      cloudflareResult = { ok: false, stage: 'tunnel-start', code, host: cloudflareHost, port: 443, tls: true };
      console.log(`CF_TUNNEL_FAILED mode=${named ? 'named' : 'quick'} code=${code}`);
    }

    api.setIngressSelfTest('cloudflare', cloudflareResult);

    if (cloudflareResult.ok) {
      api.setIngressEndpoint('cloudflare', {
        host: cloudflareHost,
        port: 443,
        tls: true,
        mode: cloudflareMode
      }, 'cloudflare-selftest');
      console.log(`CF_WS_SELFTEST_READY target=${cloudflareResult.target} endpoint=${cloudflareHost}:443 tls=on mode=${cloudflareMode}`);
      const cfSub = api.getSubscriptionUrl('cloudflare', true);
      if (cfSub) console.log(`SUB_CF_READY ${cfSub}`);
    } else {
      console.log(`CF_WS_SELFTEST_FAILED ${resultDetail(cloudflareResult)} endpoint=${cloudflareHost || 'missing'}:443 mode=${cloudflareMode}`);
    }
  } else {
    api.setIngressSelfTest('cloudflare', { ok: false, stage: 'configuration' });
    console.log('CF_WS_SELFTEST_SKIPPED reason=cloudflare-tunnel-not-configured');
  }

  const nativeReady = !!nativeResult.ok;
  const cloudflareReady = !!cloudflareResult.ok;
  const readyCount = Number(nativeReady) + Number(cloudflareReady);

  if (readyCount === 2) {
    console.log(`DUAL_INGRESS_READY logical_nodes=1 node_id=${identity.nodeId} native=${nativeHost}:443 cloudflare=${cloudflareHost}:443`);
  } else if (readyCount === 1) {
    console.log(`DUAL_INGRESS_DEGRADED logical_nodes=1 node_id=${identity.nodeId} native=${nativeReady ? 'ready' : 'failed'} cloudflare=${cloudflareReady ? 'ready' : 'failed'}`);
  } else {
    console.log(`DUAL_INGRESS_FAILED logical_nodes=1 node_id=${identity.nodeId}`);
  }

  // Registry stays one logical node. Prefer Cloudflare as the single registry
  // endpoint; fall back to native only if Cloudflare is unavailable.
  let primaryKind = '';
  if (cloudflareReady) primaryKind = 'cloudflare';
  else if (nativeReady) primaryKind = 'native';

  if (primaryKind) api.setPrimaryIngress(primaryKind);

  const combined = {
    ok: readyCount > 0,
    logical_nodes: 1,
    local,
    native: nativeResult,
    cloudflare: cloudflareResult,
    primary_ingress: primaryKind || null
  };
  saveResult(combined);

  if (!primaryKind) {
    console.log('REGISTRY_HELD reason=no-public-ingress-ready');
    return;
  }

  if (quick && !named && primaryKind === 'cloudflare') {
    console.log('REGISTRY_HELD reason=quick-tunnel-diagnostic');
    return;
  }

  if (!enabled(process.env.INFRLO_ENABLE_REGISTRY)) {
    console.log('REGISTRY_HELD reason=registry-disabled');
    return;
  }

  try {
    const activated = await api.activateRegistryAfterSelfTest();
    if (!activated) console.log('REGISTRY_ACTIVATION_PENDING_AFTER_PUBLIC_SELFTEST');
  } catch (e) {
    const code = String(e?.message || e || 'ERR').replace(/\s+/g, '_').slice(0, 100);
    console.log(`REGISTRY_ACTIVATION_FAILED_AFTER_PUBLIC_SELFTEST code=${code}`);
  }
}

setTimeout(() => {
  run().catch(e => {
    const code = String(e?.message || e || 'ERR').replace(/\s+/g, '_').slice(0, 100);
    console.log(`PUBLIC_WS_SELFTEST_FAILED stage=exception code=${code}`);
  });
}, 4000).unref();

module.exports = { run, localAttempt, publicAttempt, resolveIpv4ViaDoh, waitForIpv4 };
