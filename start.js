'use strict';

// Infrlo does not currently document a public runtime-port contract.
// Respect an injected PORT when present; otherwise use the common PaaS default 3000.
if (!String(process.env.PORT || '').trim()) {
  process.env.PORT = '3000';
}

require('./index.js');
