'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

test('dual Registry implementation keeps legacy CF id and adds Native id', () => {
  const source = fs.readFileSync(require.resolve('../index.js'), 'utf8');

  assert.match(source, /return kind === 'cloudflare' \? identity\.nodeId : `\$\{identity\.nodeId\}-native`/);
  assert.match(source, /registryNodeName\(kind\)/);
  assert.match(source, /nodeUri\(ep, kind === 'cloudflare' \? 'CF' : 'Native'\)/);
  assert.match(source, /subscription_url: target\.subscriptionUrl/);
  assert.match(source, /for \(const kind of kinds\)/);
  assert.match(source, /REGISTRY_READY endpoints=\$\{okCount\}\/\$\{kinds\.length\}/);
  assert.match(source, /heartbeatEndpoint\(kind\)/);
  assert.match(source, /REGISTRY_CF_IDENTITY_REPAIRED/);
  assert.match(source, /registerEndpoint\('cloudflare', \{ allowConfigured: true \}\)/);
});
