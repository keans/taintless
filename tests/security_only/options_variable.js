const jwt = require('jsonwebtoken');
function options_in_a_variable(req, token, key) {
  const opts = { algorithms: [req.query.alg] };
  return jwt.verify(token, key, opts);
}
function clean_variable(req, token, key) {
  const opts = { audience: req.query.aud, algorithms: ['HS256'] };
  return jwt.verify(token, key, opts);
}
