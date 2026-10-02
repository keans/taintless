const { exec } = require("child_process");

function handler(req, res, db) {
  const name = req.query.name;
  exec("ls " + name);
  res.send("<h1>" + name + "</h1>");
  eval(req.body.code);
  const id = parseInt(req.query.id);
  db.query("SELECT * FROM t WHERE id=" + id);
  db.query("SELECT * FROM t WHERE n='" + name + "'");
}
