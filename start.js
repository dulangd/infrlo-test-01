'use strict';

// Infrlo's own public Node.js sample listens on 0.0.0.0:5000.
// Force the app to the platform's expected internal web port so its router can reach us.
process.env.PORT = '5000';

require('./index.js');
