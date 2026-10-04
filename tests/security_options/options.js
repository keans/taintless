const jwt = require('jsonwebtoken');

function verifyLiteral(token, key, opts) {
  return jwt.verify(token, key, opts);
}
function verifyVariable(token, key, opts) {
  return jwt.verify(token, key, opts);
}
function verifyChain(token, key, opts) {
  return jwt.verify(token, key, opts);
}
function verifyClean(token, key, opts) {
  return jwt.verify(token, key, opts);
}
function passed_literal(req, token, key) {
  return verifyLiteral(token, key, { algorithms: [req.query.alg] });
}
function passed_variable(req, token, key) {
  const opts = { algorithms: [req.query.alg] };
  return verifyVariable(token, key, opts);
}
function passed_on(token, key, opts) {
  return verifyChain(token, key, opts);
}
function passed_on_literal(req, token, key) {
  return passed_on(token, key, { algorithms: [req.query.alg] });
}
function passed_clean(req, token, key) {
  return verifyClean(token, key, { audience: req.query.aud, algorithms: ['HS256'] });
}
function build(req) {
  return { algorithms: [req.query.alg] };
}
function build_clean(req) {
  return { audience: req.query.aud, algorithms: ['HS256'] };
}
function returned_direct(req, token, key) {
  return jwt.verify(token, key, build(req));
}
function returned_variable(req, token, key) {
  const o = build(req);
  return jwt.verify(token, key, o);
}
function returned_clean(req, token, key) {
  const o = build_clean(req);
  return jwt.verify(token, key, o) && jwt.verify(token, key, build_clean(req));
}
