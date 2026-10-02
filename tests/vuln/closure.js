const { exec } = require("child_process");
function run(req) {
  const cmd = req.query.cmd;
  const go = () => exec(cmd);
  go();
}
