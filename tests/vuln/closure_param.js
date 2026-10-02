const { exec } = require("child_process");

function run(cmd) {
  const go = () => exec(cmd);
  go();
}

function main(req) {
  run(req.query.cmd);
}
