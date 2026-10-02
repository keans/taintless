function run(user) {
  [user].forEach((v) => { exec(v); });
}

function stored(user) {
  const cb = (v) => { exec(v); };
  [user].forEach(cb);
}

function named(user) {
  const h = sink;
  h(user);
}

function sink(x) {
  exec(x);
}

function capture(req) {
  const cmd = req.query.cmd;
  const go = () => exec(cmd);
  go();
}
