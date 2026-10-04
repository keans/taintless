import CJ from 'crypto-js';
import { SHA1 as sha1 } from 'crypto-js';
const forge = require('node-forge');
function f(x, k) {
  CJ.MD5(x);
  CJ.AES.encrypt(x, k);
  sha1(x);
}
