const jwt = require('jsonwebtoken');

function build_by_key(req) {
  const o = {};
  o.algorithms = [req.query.alg];
  return o;
}
function by_key_direct(req, token, key) {
  return jwt.verify(token, key, build_by_key(req));
}
function build_reassigned(req) {
  let o = { audience: 'a' };
  o = { algorithms: [req.query.alg] };
  return o;
}
function reassigned_direct(req, token, key) {
  return jwt.verify(token, key, build_reassigned(req));
}
function build_clean(req) {
  const o = {};
  o.audience = req.query.aud;
  o.algorithms = ['HS256'];
  return o;
}
function by_key_clean(req, token, key) {
  return jwt.verify(token, key, build_clean(req));
}
function key_by_key_here(req, token, key) {
  const o = {};
  o.algorithms = [req.query.alg];
  return jwt.verify(token, key, o);
}
class Checker {
  constructor(req) {
    this.opts = { algorithms: [req.query.alg] };
    this.safe = { audience: req.query.aud, algorithms: ['HS256'] };
  }
  check(token, key) {
    return jwt.verify(token, key, this.opts);
  }
  check_safe(token, key) {
    return jwt.verify(token, key, this.safe);
  }
}
function in_container(req, token, key) {
  const all = { jwt: { algorithms: [req.query.alg] } };
  return jwt.verify(token, key, all.jwt);
}
