const jwt = require('jsonwebtoken');
const tls = require('tls');
function algorithm_from_request(req, token, key) {
  return jwt.verify(token, key, { algorithms: [req.query.alg] });
}
function other_option_is_tainted(req, token, key) {
  return jwt.verify(token, key, { audience: req.query.aud, algorithms: ['HS256'] });
}
function signing_algorithm(req, payload, key) {
  return jwt.sign(payload, key, { algorithm: req.body.alg, expiresIn: '1h' });
}
function tls_version(req) {
  return tls.connect({ host: 'example.org', minVersion: req.query.v });
}
function constant_options(req, token, key) {
  return jwt.verify(token, key, { algorithms: ['RS256'], audience: req.query.aud });
}
function nested_options(req) {
  return tls.connect({ host: 'example.org', secureContext: { minVersion: req.query.v } });
}
