const handlers = { run: sink };

function dispatch(user) {
  handlers.run(user);
}

class Bus {
  constructor() { this.cb = sink; }
  fire(x) { this.cb(x); }
}

function reassign(user) {
  let f = noop;
  f = sink;
  f(user);
}

function sink(x) { exec(x); }
function noop(y) { return y; }
