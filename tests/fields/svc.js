const { exec } = require("child_process");

class S {
  load(req) {
    this.c = req.query.c;
  }

  run() {
    exec(this.c);
    exec(this.n);
  }
}
