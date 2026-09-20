'use strict';

const rawPort = String(process.env.PORT || '').trim();
if (!rawPort) {
  process.env.PORT = '5000';
  console.log('[boot] PORT not provided by platform; using Infrlo fallback 5000');
} else {
  console.log('[boot] using platform PORT=' + rawPort);
}

require('./index.js');
