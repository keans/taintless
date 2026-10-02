function open() {}
function close() {}

const table = { open: open, close: close };

function dispatch(name) {
  table[name]();
}

function each() {
  const hs = [open, close];
  for (const h of hs) {
    h();
  }
}

function handed(register) {
  const hs = [open];
  register(hs);
}

function keyed() {
  const t = { open: open, close: close };
  t["close"]();
  t.open();
}
