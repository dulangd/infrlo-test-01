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

if (!String(process.env.INFRLO_NATIVE_HOST || '').trim()) {
  process.env.INFRLO_NATIVE_HOST = 'qqnioc.infrlo.com';
}

const nativeHost = String(process.env.INFRLO_NATIVE_HOST || '').trim().toLowerCase();
const cfHost = String(process.env.CF_TUNNEL_HOSTNAME || '').trim().toLowerCase();
const namedTunnel = !!(
  String(process.env.CF_TUNNEL_TOKEN || '').trim() &&
  cfHost
);
const quickTunnel = enabled(process.env.INFRLO_CF_QUICK_TUNNEL);
const primaryIngress = String(process.env.INFRLO_PRIMARY_INGRESS || 'cloudflare').trim().toLowerCase() === 'native' ? 'native' : 'cloudflare';

process.env.REGISTRY_REQUIRE_PUBLIC_SELFTEST = '1';

console.log(
  '[boot] dual-ingress logical_nodes=1' +
  ' native=' + (nativeHost || 'disabled') +
  ' cloudflare=' + (cfHost || (quickTunnel ? 'quick-tunnel' : 'disabled')) +
  ' primary=' + primaryIngress
);

require('./index.js');

// v1.2.0 always self-tests the native ingress. Cloudflare is tested too when
// Named/Quick Tunnel is configured.
require('./public-selftest.js');
