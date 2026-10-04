package demo

import java.security.MessageDigest
import javax.crypto.Cipher as C
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec

const val ALGO = "DES/ECB/PKCS5Padding"
val KEY = "0123456789abcdef".toByteArray()

class CryptoDemo {
    fun hashes(data: ByteArray): ByteArray {
        val md5 = MessageDigest.getInstance("MD5")
        val sha = MessageDigest.getInstance("SHA-256")
        sha.digest(data)
        return md5.digest(data)
    }

    fun encrypt(data: ByteArray): ByteArray {
        val c = C.getInstance(ALGO)
        c.init(C.ENCRYPT_MODE, SecretKeySpec(KEY, "DES"), IvParameterSpec(ByteArray(8)))
        val ok = C.getInstance("AES/GCM/NoPadding")
        return c.doFinal(data)
    }

    fun pinned() {
        val spec = SecretKeySpec(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), "AES")
    }
}
