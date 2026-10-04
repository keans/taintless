const crypto = require('crypto');
function f(req) { return crypto.createHash(req.query.alg); }
function g(req) { return crypto.createHash('sha256'); }
