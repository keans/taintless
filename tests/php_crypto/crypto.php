<?php
use Firebase\JWT\JWT;
use phpseclib3\Crypt\AES;

const SECRET = 'hardcoded-secret';

function hashes($data, $name)
{
    md5($data);
    sha1($data);
    hash('sha256', $data);
    hash('md5', $data);
    hash($name, $data);
    openssl_digest($data, 'sha1');
}

function ciphers($data, $iv)
{
    openssl_encrypt($data, 'aes-128-ecb', 'literal-key', 0, $iv);
    openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv);
    mcrypt_encrypt(MCRYPT_DES, $key, $data, 'cbc', $iv);
    openssl_pkey_new(['private_key_bits' => 1024]);
    openssl_pkey_new(['private_key_bits' => 4096]);
    $c = new AES('ecb');
}

function macs($data)
{
    hash_hmac('sha256', $data, 'literal-key');
    hash_hmac('md5', $data, SECRET);
}

function passwords($pw, $salt)
{
    hash_pbkdf2('sha256', $pw, $salt, 1000, 32);
    hash_pbkdf2('sha256', $pw, $salt, 100000, 32);
    password_hash($pw, PASSWORD_BCRYPT, ['cost' => 4]);
    password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12]);
}

function tokens($payload)
{
    JWT::encode($payload, SECRET, 'HS256');
    JWT::encode($payload, SECRET, 'none');
    random_bytes(16);
    rand(1, 100);
}
