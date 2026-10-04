const argon2 = require('argon2');
const crypto = require('crypto');
const ALGS = { fast: 'md5', safe: 'sha256' };
const WEAK = { memoryCost: 4096, timeCost: 3 };
const GOOD = { memoryCost: 65536, timeCost: 3 };
const LEVEL = 5;

async function f(pw) {
  crypto.createHash(ALGS.fast);
  crypto.createHash(ALGS.safe);
  crypto.createHash(`md${LEVEL}`);
  await argon2.hash(pw, WEAK);
  await argon2.hash(pw, GOOD);
}
