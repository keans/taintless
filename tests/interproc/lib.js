const { exec } = require("child_process");

function sh(cmd) {
  exec(cmd);
}

module.exports = { sh };
