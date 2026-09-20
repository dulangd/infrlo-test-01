'use strict';

function enabled(v) {
  return /^(1|true|yes|on)$/i.test(String(v || ''));
}

const rawPort = String(process.env.PORT || '').trim();
if (!rawPort) {
  process.env.PORT = '5000';
  console.log('[boot] PORT not provided by platform; using Infrlo fallback 5000');
} else {
  console.log('[boot] using platform PORT=' + rawPort);
}

const namedTunnel = !!(
  String(process.env.CF_TUNNEL_TOKEN || '').trim() &&
  String(process.env.CF_TUNNEL_HOSTNAME || '').trim()
);
const quickTunnel = enabled(process.env.INFRLO_CF_QUICK_TUNNEL);

if (namedTunnel || quickTunnel) {
  process.env.REGISTRY_REQUIRE_PUBLIC_SELFTEST = '1';
  console.log('[boot] Cloudflare tunnel mode=' + (namedTunnel ? 'named' : 'quick') + '; Railway registration gated');
}

require('./index.js');

if (namedTunnel || quickTunnel) {
  require('./public-selftest.js');
}
