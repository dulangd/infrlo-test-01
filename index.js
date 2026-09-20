#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');
const crypto = require('crypto');

const VERSION = '1.1.3';
const PROVIDER = 'infrlo';
const HOST = '0.0.0.0';
const PORT = validPort(process.env.PORT) || 8080;
const APP_DIR = __dirname;
const HOME_FILE = path.join(APP_DIR, 'index.html');
const STATE_DIR = process.env.STATE_DIR || path.join(APP_DIR, '.state');
const IDENTITY_FILE = path.join(STATE_DIR, 'identity.json');
const ENDPOINT_FILE = path.join(STATE_DIR, 'public-endpoint.json');
const REGISTRY_PROOF_FILE = path.join(STATE_DIR, 'registry-proof.txt');
const REGISTRY_URL = clean(process.env.REGISTRY_URL || 'https://subscription-server-v2-production.up.railway.app').replace(/\/+$/, '');
const REGISTRY_TOKEN = clean(process.env.REGISTRY_TOKEN);
const HEARTBEAT_MS = Math.max(60_000, Number(process.env.HEARTBEAT_MS || 600000));
const REGISTRY_REQUIRE_PUBLIC_SELFTEST = /^(1|true|yes|on)$/i.test(String(process.env.REGISTRY_REQUIRE_PUBLIC_SELFTEST || '0'));
const TUNNEL_MODE = /^(1|true|yes|on)$/i.test(String(process.env.INFRLO_CF_QUICK_TUNNEL || '0')) || !!(clean(process.env.CF_TUNNEL_TOKEN) && clean(process.env.CF_TUNNEL_HOSTNAME));
const ENDPOINT_OVERRIDE = clean(process.env.PUBLIC_ENDPOINT);

function clean(v) { return String(v || '').trim(); }
function validPort(v) {
  const n = Number(v);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? n : 0;
}
function randomToken(bytes = 18) { return crypto.randomBytes(bytes).toString('base64url'); }
function sha256(v) { return crypto.createHash('sha256').update(String(v)).digest('hex'); }
function isUuid(v) { return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(clean(v)); }
function safeJsonRead(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return {}; } }
function atomicJsonWrite(file, value) {
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + '.tmp-' + process.pid;
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
    return true;
  } catch {
    return false;
  }
}
function constantTimeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function normalizeWsPath(v) {
  const s = clean(v).replace(/^\/+|\/+$/g, '');
  return '/' + (s || ('ws-' + randomToken(12)));
}
function stripCountryPrefix(name) {
  const n = clean(name) || 'Infrlo-01';
  return n.replace(/^[A-Z]{2}-/i, '') || 'Infrlo-01';
}

function loadIdentity() {
  const saved = safeJsonRead(IDENTITY_FILE);
  const envUuid = clean(process.env.UUID);
  const value = {
    uuid: isUuid(envUuid) ? envUuid : (isUuid(saved.uuid) ? saved.uuid : crypto.randomUUID()),
    wsPath: normalizeWsPath(process.env.WS_PATH || saved.wsPath),
    subToken: clean(process.env.SUB_TOKEN) || saved.subToken || randomToken(24),
    nodeId: clean(process.env.NODE_ID) || saved.nodeId || 'infrlo-01',
    nodeNameBase: stripCountryPrefix(process.env.NODE_NAME || saved.nodeNameBase || 'Infrlo-01')
  };
  atomicJsonWrite(IDENTITY_FILE, value);
  return value;
}

function loadRegistryProof() {
  const fromEnv = clean(process.env.REGISTRY_PROOF);
  if (fromEnv.length >= 32) return fromEnv;
  try {
    const saved = clean(fs.readFileSync(REGISTRY_PROOF_FILE, 'utf8'));
    if (saved.length >= 32) return saved;
  } catch {}
  const proof = randomToken(32);
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(REGISTRY_PROOF_FILE, proof + '\n', { mode: 0o600 });
  } catch {}
  return proof;
}

const identity = loadIdentity();
const registryProof = loadRegistryProof();
const registryProofSha256 = sha256(registryProof);

let countryState = {
  code: 'XX', verified: false, egressIp: null, checkedAt: null, sources: {}, mismatch: false
};
let countryPromise = null;
let countryLastAttempt = 0;

async function fetchJson(url, timeout = 7000) {
  const r = await fetch(url, {
    headers: { 'user-agent': 'infrlo-node/' + VERSION },
    signal: AbortSignal.timeout(timeout)
  });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}
async function fetchText(url, timeout = 7000) {
  const r = await fetch(url, {
    headers: { 'user-agent': 'infrlo-node/' + VERSION },
    signal: AbortSignal.timeout(timeout)
  });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.text();
}
function validCountry(v) {
  const s = clean(v).toUpperCase();
  return /^[A-Z]{2}$/.test(s) ? s : null;
}

async function verifyCountry(force = false) {
  const now = Date.now();
  if (!force && countryState.checkedAt && countryState.verified) return countryState;
  if (!force && countryPromise) return countryPromise;
  if (!force && now - countryLastAttempt < 60_000 && countryState.checkedAt) return countryState;
  countryLastAttempt = now;

  countryPromise = (async () => {
    const sources = {};
    let cf = null;
    let ipinfo = null;
    try {
      const text = await fetchText('https://www.cloudflare.com/cdn-cgi/trace');
      const kv = Object.fromEntries(text.split(/\r?\n/).map(line => line.split('=')).filter(x => x.length === 2));
      cf = { country: validCountry(kv.loc), ip: clean(kv.ip) || null };
      if (cf.country) sources.cloudflare = cf;
    } catch (e) { sources.cloudflare_error = e.message; }
    try {
      const j = await fetchJson('https://ipinfo.io/json');
      ipinfo = { country: validCountry(j.country), ip: clean(j.ip) || null };
      if (ipinfo.country) sources.ipinfo = ipinfo;
    } catch (e) { sources.ipinfo_error = e.message; }

    const codes = [cf?.country, ipinfo?.country].filter(Boolean);
    let code = 'XX';
    let verified = false;
    let mismatch = false;
    if (codes.length >= 2) {
      if (codes.every(x => x === codes[0])) { code = codes[0]; verified = true; }
      else mismatch = true;
    } else if (codes.length === 1) code = codes[0];

    countryState = {
      code: mismatch ? 'XX' : code,
      verified,
      egressIp: cf?.ip || ipinfo?.ip || null,
      checkedAt: new Date().toISOString(),
      sources,
      mismatch
    };

    if (verified) console.log(`[geo] verified country=${countryState.code} ip=${countryState.egressIp || 'unknown'}`);
    else if (mismatch) console.warn('[geo] country sources disagree; keeping XX');
    else console.warn(`[geo] country=${countryState.code} unverified; will retry`);

    if (publicEndpoint?.host) scheduleRegistration(500);
    return countryState;
  })().finally(() => { countryPromise = null; });
  return countryPromise;
}

function nodeName() { return `${countryState.code || 'XX'}-${identity.nodeNameBase}`; }

function parseEndpointString(value) {
  if (!value) return null;
  try {
    const u = new URL(value.includes('://') ? value : ('https://' + value));
    const protocol = u.protocol === 'http:' ? 'http' : 'https';
    const port = validPort(u.port) || (protocol === 'https' ? 443 : 80);
    if (!u.hostname) return null;
    return { protocol, host: u.hostname, port, source: 'override', learnedAt: new Date().toISOString() };
  } catch { return null; }
}
function endpointScore(ep) {
  if (!ep?.host) return -1;
  let score = 0;
  if (ep.protocol === 'https') score += 100;
  if (!net.isIP(ep.host)) score += 40;
  if (ep.port === 443) score += 20;
  if (ep.source === 'override') score += 200;
  if (String(ep.source || '').includes('selftest') || String(ep.source || '').includes('cloudflare')) score += 180;
  return score;
}
function loadEndpoint() {
  const override = parseEndpointString(ENDPOINT_OVERRIDE);
  if (override) return override;
  if (TUNNEL_MODE) return null;
  return safeJsonRead(ENDPOINT_FILE);
}

let publicEndpoint = loadEndpoint();
let registerTimer = null;
let registered = false;
let registryActivated = !REGISTRY_REQUIRE_PUBLIC_SELFTEST;
let registryWaitLogged = false;
let registryLastStatus = null;
let registryLastError = '';
let registryLastAttemptAt = null;
let registryLastSuccessAt = null;
let bytesUp = 0;
let bytesDown = 0;
let connections = 0;

function learnEndpoint(req) {
  if (ENDPOINT_OVERRIDE) return;
  const xfProto = clean(String(req.headers['x-forwarded-proto'] || '').split(',')[0]).toLowerCase();
  const xfHost = clean(String(req.headers['x-forwarded-host'] || '').split(',')[0]);
  const rawHost = xfHost || clean(req.headers.host);
  if (!rawHost) return;
  let hostUrl;
  try { hostUrl = new URL('http://' + rawHost); } catch { return; }
  const host = hostUrl.hostname;
  if (!host || host === 'localhost' || host === '127.0.0.1' || host === '::1') return;

  const xfPort = validPort(String(req.headers['x-forwarded-port'] || '').split(',')[0]);
  let protocol = req.socket.encrypted ? 'https' : 'http';
  if (xfProto === 'https') protocol = 'https';
  else if (xfProto === 'http') protocol = 'http';
  else if (xfPort === 443) protocol = 'https';
  const port = xfPort || validPort(hostUrl.port) || (protocol === 'https' ? 443 : 80);
  const candidate = { protocol, host, port, source: 'request', learnedAt: new Date().toISOString() };

  if (!publicEndpoint || endpointScore(candidate) >= endpointScore(publicEndpoint)) {
    const changed = !publicEndpoint || candidate.protocol !== publicEndpoint.protocol || candidate.host !== publicEndpoint.host || candidate.port !== publicEndpoint.port;
    publicEndpoint = candidate;
    atomicJsonWrite(ENDPOINT_FILE, candidate);
    if (changed) {
      console.log(`[endpoint] learned ${candidate.protocol}://${candidate.host}:${candidate.port}`);
      scheduleRegistration(800);
    }
  }
}
function currentEndpoint(req) { if (req) learnEndpoint(req); return publicEndpoint?.host ? publicEndpoint : null; }

function setPublicEndpoint(endpoint, source = 'runtime') {
  const host = clean(endpoint?.host).toLowerCase();
  const tlsEnabled = !!endpoint?.tls;
  const port = validPort(endpoint?.port) || (tlsEnabled ? 443 : 80);
  if (!host || host === 'localhost' || host === '127.0.0.1' || host === '::1') return false;

  const candidate = {
    protocol: tlsEnabled ? 'https' : 'http',
    host,
    port,
    source,
    mode: clean(endpoint?.mode) || 'runtime',
    learnedAt: new Date().toISOString()
  };

  publicEndpoint = candidate;
  atomicJsonWrite(ENDPOINT_FILE, candidate);
  process.env.PUBLIC_ENDPOINT = `${candidate.protocol}://${candidate.host}:${candidate.port}`;
  console.log(`[endpoint] ready source=${source} mode=${candidate.mode} ${candidate.protocol}://${candidate.host}:${candidate.port}`);
  return true;
}

function formatHost(host) { return net.isIP(host) === 6 ? `[${host}]` : host; }
function baseUrl(ep) {
  const defaultPort = (ep.protocol === 'https' && ep.port === 443) || (ep.protocol === 'http' && ep.port === 80);
  return `${ep.protocol}://${formatHost(ep.host)}${defaultPort ? '' : ':' + ep.port}`;
}
function nodeUri(ep) {
  if (!ep) return null;
  const secure = ep.protocol === 'https';
  const qp = new URLSearchParams({ encryption: 'none', security: secure ? 'tls' : 'none', type: 'ws', host: ep.host, path: identity.wsPath });
  if (secure) { qp.set('sni', ep.host); qp.set('alpn', 'http/1.1'); }
  return `vless://${identity.uuid}@${formatHost(ep.host)}:${ep.port}?${qp.toString()}#${encodeURIComponent(nodeName())}`;
}

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'x-frame-options': 'DENY',
    'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
  });
  res.end(body);
}
function notFound(res) { send(res, 404, 'Not found\n'); }
function authorizedToken(v) { return constantTimeEqual(v, identity.subToken); }

const requestHandler = (req, res) => {
  learnEndpoint(req);
  let url;
  try { url = new URL(req.url, 'http://local'); } catch { return notFound(res); }
  if (req.method !== 'GET' && req.method !== 'HEAD') return notFound(res);
  const bodyless = req.method === 'HEAD';

  if (url.pathname === '/health') {
    const ep = currentEndpoint(req);
    const payload = {
      ok: true,
      service: 'infrlo-node',
      version: VERSION,
      provider: PROVIDER,
      node_id: identity.nodeId,
      node_name: nodeName(),
      endpoint_ready: !!ep,
      endpoint: ep ? `${ep.protocol}://${ep.host}:${ep.port}` : null,
      geo: { country: countryState.code, verified: countryState.verified, mismatch: countryState.mismatch, egress_ip: countryState.egressIp, checked_at: countryState.checkedAt },
      traffic: { connections, upload_bytes: bytesUp, download_bytes: bytesDown },
      registry_proof_sha256: registryProofSha256,
      registry: { configured: true, auth_mode: REGISTRY_TOKEN ? 'bearer-token' : 'public-proof', url: REGISTRY_URL, require_public_selftest: REGISTRY_REQUIRE_PUBLIC_SELFTEST, activated: registryActivated, registered, last_status: registryLastStatus, last_error: registryLastError || null, last_attempt_at: registryLastAttemptAt, last_success_at: registryLastSuccessAt }
    };
    return send(res, 200, bodyless ? '' : JSON.stringify(payload), 'application/json; charset=utf-8');
  }

  const p = url.pathname.split('/').filter(Boolean);
  let action = null;
  let token = null;
  if (p.length === 2 && ['sub', 'sub64', 'node'].includes(p[1])) { token = p[0]; action = p[1]; }
  if (p.length === 2 && p[0] === 'sub') { token = p[1]; action = 'sub64'; }
  if (action) {
    if (!authorizedToken(token)) return notFound(res);
    const ep = currentEndpoint(req);
    if (!ep) return send(res, 503, 'Public endpoint not learned yet\n');
    const uri = nodeUri(ep);
    if (action === 'sub') return send(res, 200, bodyless ? '' : uri + '\n');
    if (action === 'sub64') return send(res, 200, bodyless ? '' : Buffer.from(uri + '\n').toString('base64'));
    const payload = { version: 1, provider: PROVIDER, node_id: identity.nodeId, name: nodeName(), endpoint: ep, country: countryState.code, country_verified: countryState.verified, ws_path: identity.wsPath, uri, individual_subscription: baseUrl(ep) + '/' + identity.subToken + '/sub', individual_subscription_base64: baseUrl(ep) + '/' + identity.subToken + '/sub64' };
    return send(res, 200, bodyless ? '' : JSON.stringify(payload, null, 2), 'application/json; charset=utf-8');
  }

  if (url.pathname === '/') {
    let html = '<!doctype html><meta charset="utf-8"><title>Green Horizon</title><h1>Green Horizon</h1>';
    try { html = fs.readFileSync(HOME_FILE, 'utf8'); } catch {}
    return send(res, 200, bodyless ? '' : html, 'text/html; charset=utf-8');
  }
  return notFound(res);
};

const server = http.createServer(requestHandler);
server.keepAliveTimeout = 65_000;
server.headersTimeout = 70_000;

function wsAccept(key) { return crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64'); }
function wsFrame(payload, opcode = 2) {
  payload = Buffer.from(payload);
  const n = payload.length;
  let h;
  if (n < 126) { h = Buffer.alloc(2); h[0] = 0x80 | opcode; h[1] = n; }
  else if (n <= 0xffff) { h = Buffer.alloc(4); h[0] = 0x80 | opcode; h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x80 | opcode; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([h, payload]);
}
function createWsParser(onMessage, onPing, onClose) {
  let buf = Buffer.alloc(0);
  let fragmentedOpcode = null;
  let fragments = [];
  let fragmentedBytes = 0;
  const MAX_MESSAGE = 8 * 1024 * 1024;
  return chunk => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const b0 = buf[0], b1 = buf[1];
      const fin = !!(b0 & 0x80);
      const opcode = b0 & 0x0f;
      const masked = !!(b1 & 0x80);
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; const big = buf.readBigUInt64BE(2); if (big > BigInt(MAX_MESSAGE)) return onClose(); len = Number(big); off = 10; }
      if (!masked || len > MAX_MESSAGE) return onClose();
      if (buf.length < off + 4 + len) return;
      const mask = buf.subarray(off, off + 4); off += 4;
      const payload = Buffer.from(buf.subarray(off, off + len));
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
      buf = buf.subarray(off + len);
      if (opcode === 8) return onClose();
      if (opcode === 9) { onPing(payload); continue; }
      if (opcode === 10) continue;
      if (opcode === 0) {
        if (fragmentedOpcode === null) return onClose();
        fragments.push(payload); fragmentedBytes += payload.length;
        if (fragmentedBytes > MAX_MESSAGE) return onClose();
        if (fin) { const message = Buffer.concat(fragments, fragmentedBytes); const op = fragmentedOpcode; fragmentedOpcode = null; fragments = []; fragmentedBytes = 0; onMessage(op, message); }
        continue;
      }
      if (opcode !== 1 && opcode !== 2) return onClose();
      if (fin) onMessage(opcode, payload);
      else { fragmentedOpcode = opcode; fragments = [payload]; fragmentedBytes = payload.length; }
    }
  };
}

server.on('upgrade', (req, socket, head) => {
  learnEndpoint(req);
  let pathname = '';
  try { pathname = new URL(req.url, 'http://local').pathname; } catch {}
  if (pathname !== identity.wsPath || clean(req.headers.upgrade).toLowerCase() !== 'websocket') {
    socket.end('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
    return;
  }
  const key = clean(req.headers['sec-websocket-key']);
  if (!key) { socket.destroy(); return; }
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + wsAccept(key) + '\r\n\r\n');
  socket.setNoDelay(true);

  let remote = null;
  let initialized = false;
  let closed = false;
  connections += 1;
  const close = () => {
    if (closed) return;
    closed = true;
    try { remote?.destroy(); } catch {}
    try { socket.destroy(); } catch {}
  };
  const parser = createWsParser((opcode, payload) => {
    if (opcode !== 2) return;
    bytesUp += payload.length;
    if (!initialized) {
      initialized = true;
      const reqInfo = parseVless(payload);
      if (!reqInfo) return close();
      remote = net.connect({ host: reqInfo.address, port: reqInfo.port, timeout: 12_000 });
      remote.setNoDelay(true);
      remote.once('connect', () => {
        if (closed || socket.destroyed) return close();
        socket.write(wsFrame(Buffer.from([0, 0])));
        if (reqInfo.payload.length) remote.write(reqInfo.payload);
      });
      remote.on('data', d => {
        bytesDown += d.length;
        if (!closed && !socket.destroyed) { try { socket.write(wsFrame(d)); } catch { close(); } }
      });
      remote.on('timeout', close);
      remote.on('error', close);
      remote.on('close', close);
      return;
    }
    if (remote && !remote.destroyed) remote.write(payload);
  }, payload => {
    try { if (!socket.destroyed) socket.write(wsFrame(payload, 10)); } catch { close(); }
  }, close);
  if (head?.length) parser(head);
  socket.on('data', parser);
  socket.on('error', close);
  socket.on('close', () => { try { remote?.destroy(); } catch {} });
});

function parseVless(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 24 || buf[0] !== 0) return null;
  const id = [buf.subarray(1, 5), buf.subarray(5, 7), buf.subarray(7, 9), buf.subarray(9, 11), buf.subarray(11, 17)].map(x => x.toString('hex')).join('-');
  if (!constantTimeEqual(id.toLowerCase(), identity.uuid.toLowerCase())) return null;
  let p = 17;
  const optLen = buf[p++]; p += optLen;
  if (buf.length < p + 4) return null;
  const command = buf[p++];
  if (command !== 1) return null;
  const port = buf.readUInt16BE(p); p += 2;
  const atyp = buf[p++];
  let address;
  if (atyp === 1) { if (buf.length < p + 4) return null; address = [...buf.subarray(p, p + 4)].join('.'); p += 4; }
  else if (atyp === 2) { if (buf.length < p + 1) return null; const n = buf[p++]; if (buf.length < p + n) return null; address = buf.subarray(p, p + n).toString(); p += n; }
  else if (atyp === 3) { if (buf.length < p + 16) return null; const a = []; for (let i = 0; i < 8; i++) a.push(buf.readUInt16BE(p + i * 2).toString(16)); address = a.join(':'); p += 16; }
  else return null;
  return { address, port, payload: buf.subarray(p) };
}

function requestJson(urlString, method, body, token = '', timeout = 10_000) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlString); } catch (e) { return reject(e); }
    const lib = u.protocol === 'https:' ? https : http;
    const data = Buffer.from(JSON.stringify(body));
    const headers = { 'content-type': 'application/json', 'content-length': data.length, 'user-agent': 'container-test-infrlo/' + VERSION };
    if (token) headers.authorization = 'Bearer ' + token;
    const req = lib.request({ protocol: u.protocol, hostname: u.hostname, port: u.port || undefined, path: u.pathname + u.search, method, headers, timeout }, res => {
      let out = '';
      res.setEncoding('utf8');
      res.on('data', d => out += d);
      res.on('end', () => resolve({ status: res.statusCode, body: out }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(data);
  });
}
function scheduleRegistration(delay = 0) {
  if (!registryActivated) {
    registryLastError = 'waiting for public self-test';
    if (!registryWaitLogged) {
      registryWaitLogged = true;
      console.log('[registry] waiting for public self-test');
    }
    return;
  }
  if (!publicEndpoint?.host) { registryLastError = 'public endpoint not ready'; return; }
  clearTimeout(registerTimer);
  registerTimer = setTimeout(() => registerNode().catch(e => {
    registryLastError = e.message;
    console.warn('[registry] register failed:', e.message);
  }), delay);
}
async function registerNode() {
  if (!registryActivated) return false;
  if (!publicEndpoint?.host) return false;
  await verifyCountry();
  registryLastAttemptAt = new Date().toISOString();
  registryLastError = '';
  const uri = nodeUri(publicEndpoint);
  let r;
  if (REGISTRY_TOKEN) {
    r = await requestJson(REGISTRY_URL + '/api/v1/register', 'POST', { kind: 'proxy', node_id: identity.nodeId, name: nodeName(), provider: PROVIDER, uri, priority: 80 }, REGISTRY_TOKEN);
  } else {
    r = await requestJson(REGISTRY_URL + '/api/v1/register-public', 'POST', { provider: PROVIDER, node_id: identity.nodeId, name: nodeName(), uri, priority: 80, endpoint: baseUrl(publicEndpoint), proof: registryProof });
  }
  registryLastStatus = r.status;
  registered = r.status >= 200 && r.status < 300;
  if (!registered) {
    registryLastError = 'HTTP ' + r.status + (r.body ? ': ' + String(r.body).slice(0, 240) : '');
    throw new Error(registryLastError);
  }
  registryLastSuccessAt = new Date().toISOString();
  console.log(`[registry] registered node_id=${identity.nodeId} name=${nodeName()} mode=${REGISTRY_TOKEN ? 'bearer-token' : 'public-proof'}`);
  return true;
}
async function heartbeat() {
  if (!registryActivated || !publicEndpoint?.host) return;
  if (!countryState.verified) { try { await verifyCountry(true); } catch {} }
  if (!REGISTRY_TOKEN) {
    try { await registerNode(); } catch (e) { registered = false; registryLastError = e.message; }
    return;
  }
  try {
    const r = await requestJson(REGISTRY_URL + '/api/v1/heartbeat', 'POST', { node_id: identity.nodeId, status: 'online', traffic: { connections, upload_bytes: bytesUp, download_bytes: bytesDown } }, REGISTRY_TOKEN);
    registryLastStatus = r.status;
    if (r.status < 200 || r.status >= 300) throw new Error('HTTP ' + r.status);
    registryLastError = '';
    if (!registered) await registerNode();
  } catch (e) {
    registered = false;
    registryLastError = e.message;
    try { await registerNode(); } catch (e2) { registryLastError = e2.message; }
  }
}

async function activateRegistryAfterSelfTest() {
  if (!publicEndpoint?.host) throw new Error('public_endpoint_not_ready');
  if (!registryActivated) {
    registryActivated = true;
    registryWaitLogged = false;
    registryLastError = '';
  }
  const ok = await registerNode();
  if (ok) console.log('[registry] activated after public self-test');
  return ok;
}

server.listen(PORT, HOST, () => {
  console.log(`[ready] infrlo-node v${VERSION} ${HOST}:${PORT} http/ws`);
  console.log(`[ready] provider=${PROVIDER} node_id=${identity.nodeId}`);
  console.log(`[registry] mode=${REGISTRY_TOKEN ? 'bearer-token' : 'public-proof'} url=${REGISTRY_URL}`);
  console.log('[security] credentials, UUID, WS path, subscription token and VLESS URI are not printed');
  if (REGISTRY_REQUIRE_PUBLIC_SELFTEST) console.log('[registry] REGISTRY_WAITING_PUBLIC_SELFTEST');
  if (publicEndpoint?.host) scheduleRegistration(1000);
  else console.log('[ready] waiting for a proven public endpoint');
  verifyCountry().catch(e => console.warn('[geo] initial verification failed:', e.message));
  setInterval(heartbeat, HEARTBEAT_MS).unref();
});


module.exports = { identity, server, setPublicEndpoint, activateRegistryAfterSelfTest };
