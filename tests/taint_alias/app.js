const cp = require('child_process');
const { exec: run } = require('child_process');
function a(req) { cp.exec(req.query.c); }
function b(req) { run(req.query.c); }
function c(req) { cp.exec("ls"); }
