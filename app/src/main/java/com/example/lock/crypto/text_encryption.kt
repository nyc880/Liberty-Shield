package com.example.lock.crypto

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Arrays
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKey

/**
 * Cyber-Lab Grade Text Encryption Engine (Final Version)
 * Optimized for: Security, Anti-Forensics, and Compact Output.
 */
class TextEncryptionEngine {

    companion object {
        private const val ALGORITHM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KDF_ALGORITHM = "PBKDF2WithHmacSHA512"

        // Security Settings
        private const val ITERATIONS = 200_000
        private const val KEY_SIZE = 256
        private const val SALT_SIZE = 16
        private const val IV_SIZE = 12
        private const val TAG_SIZE = 128
        private const val BUCKET_SIZE = 64 // Traffic analysis protection

        // Protocol Flags
        private const val VERSION: Byte = 0x02
        private const val FLAG_COMPRESSED: Byte = 0x01
        private const val FLAG_UNCOMPRESSED: Byte = 0x00
    }

    /**
     * Encrypts text using a user password.
     */
    fun encrypt(plainText: String, password: CharArray): String {
        val rawBytes = plainText.toByteArray(Charsets.UTF_8)
        var salt = ByteArray(SALT_SIZE)
        var iv = ByteArray(IV_SIZE)

        try {
            // 1. Smart Compression
            val compressed = compress(rawBytes)
            val useCompression = compressed.size < rawBytes.size
            val dataToEncrypt = if (useCompression) compressed else rawBytes
            val compressionFlag = if (useCompression) FLAG_COMPRESSED else FLAG_UNCOMPRESSED

            // 2. Security Padding (Bucketing)
            val paddedData = applyBucketing(dataToEncrypt)

            // 3. Key Derivation
            SecureRandom().nextBytes(salt)
            val secretKey = deriveKey(password, salt)

            // 4. Encryption
            SecureRandom().nextBytes(iv)
            val cipher = Cipher.getInstance(ALGORITHM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(TAG_SIZE, iv))
            val ciphertext = cipher.doFinal(paddedData)

            // 5. Binary Packing [Version | Salt | IV | CompFlag | Data]
            val packet = ByteBuffer.allocate(1 + SALT_SIZE + IV_SIZE + 1 + ciphertext.size)
                .put(VERSION)
                .put(salt)
                .put(iv)
                .put(compressionFlag)
                .put(ciphertext)
                .array()

            // Memory Wipe
            paddedData.fill(0)
            if (useCompression) compressed.fill(0)

            return Base64.encodeToString(packet, Base64.URL_SAFE or Base64.NO_WRAP)

        } finally {
            rawBytes.fill(0)
            password.fill('0') // Wipe password after derivation
        }
    }

    /**
     * Decrypts text using the provided password.
     */
    fun decrypt(encryptedBase64: String, password: CharArray): String? {
        return try {
            val packet = Base64.decode(encryptedBase64, Base64.URL_SAFE or Base64.NO_WRAP)
            val buffer = ByteBuffer.wrap(packet)

            // Parse Header
            val version = buffer.get()
            if (version != VERSION) return null

            val salt = ByteArray(SALT_SIZE).also { buffer.get(it) }
            val iv = ByteArray(IV_SIZE).also { buffer.get(it) }
            val compressionFlag = buffer.get()
            val ciphertext = ByteArray(buffer.remaining()).also { buffer.get(it) }

            // Key Derivation
            val secretKey = deriveKey(password, salt)

            // Decryption
            val cipher = Cipher.getInstance(ALGORITHM_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(TAG_SIZE, iv))
            val decryptedPadded = cipher.doFinal(ciphertext)

            // Remove Padding and Decompress
            val unpadded = removeBucketing(decryptedPadded)
            val finalBytes = if (compressionFlag == FLAG_COMPRESSED) decompress(unpadded) else unpadded

            val result = String(finalBytes, Charsets.UTF_8)

            // Memory Wipe
            decryptedPadded.fill(0)
            finalBytes.fill(0)
            password.fill('0')

            result
        } catch (e: Exception) {
            null
        }
    }

    private fun deriveKey(password: CharArray, salt: ByteArray): SecretKey {
        val spec = PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE)
        val factory = SecretKeyFactory.getInstance(KDF_ALGORITHM)
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    private fun compress(data: ByteArray): ByteArray {
        val obj = ByteArrayOutputStream()
        GZIPOutputStream(obj).use { it.write(data) }
        return obj.toByteArray()
    }

    private fun decompress(data: ByteArray): ByteArray {
        return GZIPInputStream(data.inputStream()).readBytes()
    }

    private fun applyBucketing(data: ByteArray): ByteArray {
        val paddingNeeded = BUCKET_SIZE - (data.size % BUCKET_SIZE)
        val padded = ByteArray(data.size + paddingNeeded)
        System.arraycopy(data, 0, padded, 0, data.size)
        // Store padding size in the last byte
        padded[padded.lastIndex] = paddingNeeded.toByte()
        return padded
    }

    private fun removeBucketing(data: ByteArray): ByteArray {
        val paddingSize = data.last().toInt() and 0xFF
        if (paddingSize > BUCKET_SIZE) return data // Integrity error
        return data.copyOfRange(0, data.size - paddingSize)
    }
}