const crypto = require('crypto');
import { createHash } from 'node:crypto';
function f(x){ return crypto.createHash('sha1').update(x); }
