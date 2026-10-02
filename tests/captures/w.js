function handler(req) {
  let code = "";
  const load = () => { code = req.query.q; };
  load();
  eval(code);
}

function shadowed(req) {
  let code = "";
  const load = () => { let code = req.query.q; return code; };
  load();
  eval(code);
}
