const md5 = require('md5');
const sjcl = require('sjcl');
function f(x) { md5(x); sjcl.encrypt('pw', x); crypto.createSecretKey(x); }
