require 'openssl'
require 'digest'
require 'bcrypt'
require 'jwt'
require 'securerandom'

SECRET = "hardcoded-secret"

def hashes(data, name)
  Digest::MD5.hexdigest(data)
  Digest::SHA256.hexdigest(data)
  OpenSSL::Digest.new("sha1")
  OpenSSL::Digest.new(name)
  OpenSSL::Digest::SHA1.new
end

def ciphers(key)
  c = OpenSSL::Cipher.new("aes-128-ecb")
  c.encrypt
  d = OpenSSL::Cipher.new("aes-256-gcm")
  d.encrypt
  OpenSSL::Cipher::DES.new
  OpenSSL::PKey::RSA.new(1024)
  OpenSSL::PKey::RSA.generate(2048)
end

def macs(data)
  OpenSSL::HMAC.hexdigest("SHA256", "literal-key", data)
  OpenSSL::HMAC.hexdigest("MD5", SECRET, data)
end

def passwords(pw, salt)
  OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 1000, 32, "sha256")
  OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 100000, 32, "sha256")
  BCrypt::Password.create(pw, cost: 4)
  BCrypt::Password.create(pw, cost: 12)
end

def tokens(payload)
  JWT.encode(payload, SECRET, "HS256")
  JWT.decode(token, SECRET, true, algorithm: "none")
  SecureRandom.hex(16)
  rand(100)
end
