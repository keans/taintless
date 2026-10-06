import CryptoKit
import CommonCrypto
import CryptoSwift

let secret = "hardcoded-secret"

func hashes(_ data: Data) {
    Insecure.MD5.hash(data: data)
    Insecure.SHA1.hash(data: data)
    SHA256.hash(data: data)
    CC_MD5(bytes, 16, &digest)
    CC_SHA256(bytes, 16, &digest)
}

func ciphers(_ data: Data, _ key: SymmetricKey) {
    let k = SymmetricKey(data: Data("literal-key".utf8))
    AES.GCM.seal(data, using: key)
    ChaChaPoly.seal(data, using: key)
    CCCrypt(kCCEncrypt, kCCAlgorithmDES, 0, key, 8, nil, input, 16, &out, 16, &n)
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, 0, key, 32, nil, input, 16, &out, 16, &n)
    let a = try AES(key: "0123456789abcdef", iv: "0123456789abcdef")
}

func macs(_ data: Data, _ key: SymmetricKey) {
    HMAC<SHA256>.authenticationCode(for: data, using: key)
    HMAC<Insecure.MD5>.authenticationCode(for: data, using: key)
}

func passwords(_ pw: [UInt8], _ salt: [UInt8]) {
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, 8, salt, 8, kCCPRFHmacAlgSHA256, 1000, &out, 32)
    CCKeyDerivationPBKDF(kCCPBKDF2, pw, 8, salt, 8, kCCPRFHmacAlgSHA256, 100000, &out, 32)
}

func randoms() {
    SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
    arc4random_uniform(10)
    rand()
}
