const argon2 = require('argon2');
const sodium = require('sodium-native');
const farmhash = require('farmhash');
const wyhash = require('wyhash');
async function f(pw) {
  await argon2.hash(pw, { memoryCost: 4096, timeCost: 3 });
  await argon2.hash(pw, { timeCost: 3, memoryCost: 2 ** 16 });
  await argon2.hash(pw, { memoryCost: 1 << 16 });
  sodium.crypto_pwhash_str(pw, 2, sodium.crypto_pwhash_MEMLIMIT_MIN);
  farmhash.hash64(pw);
  wyhash.hash(pw);
}
