@file:Suppress("BlockingMethodInNonBlockingContext")

package com.example.lock.crypto

// =====================================================================
//  VOLATILE VAULT ENGINE — Military-Grade Secure File Deletion
//  Architecture: Crypto-Shredding (Primary) + NIST SP 800-88 Purge (Secondary)
//
//  References (all US / NIST standards):
//   – NIST SP 800-88 Rev.1  (Media Sanitization Guidelines)
//   – NIST SP 800-38D       (AES-GCM Mode of Operation)
//   – NIST SP 800-132       (PBKDF2 Password-Based Key Derivation)
//   – NIST SP 800-90A/B     (DRBG & Entropy Sources — SecureRandom)
//   – NIST SP 800-56C Rev.2 (Key Derivation Using HKDF)
//   – FIPS 140-3            (Cryptographic Module Validation)
//   – OWASP MSTG            (Mobile Security Testing Guide)
//   – JEDEC eMMC/UFS        (Flash Storage — TRIM/SECURE TRIM)
//   – DoD 5220.22-M         (3-pass overwrite pattern)
// =====================================================================

import android.content.Context
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Process
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import androidx.room.*
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.*
import java.security.spec.InvalidKeySpecException
import java.util.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import de.mkammerer.argon2.Argon2Factory

// =====================================================================
//  CONFIGURATION — NIST Compliant Constants
// =====================================================================

internal object VaultConfig {
    const val PBKDF_ITERATIONS = 600_000
    const val SALT_BYTES = 32
    const val PBKDF_KEY_BITS = 256
    const val AES_KEY_BITS = 256
    const val AES_GCM_TAG_BITS = 128
    const val GCM_NONCE_BYTES = 12
    const val CHUNK_IV_PREFIX_BYTES = 8
    val NIST_PURGE_PATTERNS = listOf(
        PurgePassType.CRYPTO_RANDOM,
        PurgePassType.ALL_ZEROES,
        PurgePassType.ALL_ONES
    )
    const val OVERWRITE_BUFFER_SIZE = 65_536
    const val AUTO_GENERATED_KEY_LENGTH = 200
    const val MIN_AUTO_GENERATED_KEY_LENGTH = 200
    const val MAX_AUTO_GENERATED_KEY_LENGTH = 300
    const val KDF_TYPE_PBKDF2 = 0
    const val KDF_TYPE_ARGON2ID = 1
    const val ARGON2_MEMORY_KB = 16384
    const val ARGON2_ITERATIONS = 3
    const val ARGON2_PARALLELISM = 1
    const val BASE_CHUNK_SIZE = 131_072
    const val STANDARD_CHUNK_SIZE = 1_048_576
    const val LOW_RAM_THRESHOLD_MB = 3072
    const val FORMAT_VERSION = 4
    const val BOUNDED_CACHE_EVICTION_MAX_BYTES = 64L * 1024L * 1024L

    // Phase 3: Room DB Hardening constants
    const val DB_NAME = "volatile_vault_db"
    const val DB_VERSION = 1
    const val PRAGMA_SECURE_DELETE = "PRAGMA secure_delete = ON"
    const val PRAGMA_SYNCHRONOUS_FULL = "PRAGMA synchronous = FULL"
    const val PRAGMA_WAL_CHECKPOINT_FULL = "PRAGMA wal_checkpoint(FULL)"
}

internal enum class PurgePassType { CRYPTO_RANDOM, ALL_ZEROES, ALL_ONES }

internal object MultiScriptPassphraseGenerator {

    private val rng = SecureRandom()

    private const val LANGUAGE_MINIMUM_PICK = 15
    private const val DIGIT_MINIMUM_PICK = 25
    private const val PUNCTUATION_MINIMUM_PICK = 15

    private data class ScriptGroup(
        val name: String,
        val tokens: List<Char>,
        val minimumPick: Int
    )

    private fun parseTokens(raw: String): List<Char> {
        return raw
            .split("-")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { it.first() }
            .distinct()
    }

    private val scriptGroups = listOf(
        ScriptGroup(
            name = "PERSIAN",
            tokens = parseTokens("ا-ب-پ-ت-ث-ج-چ-ح-خ-د-ذ-ر-ز-س-ش-ص-ض-ط-ظ-ع-غ-ف-ق-ک-گ-ل-م-ن-ه-و-ی"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "HEBREW",
            tokens = parseTokens("א-ב-ג-ד-ה-ו-ז-ח-ט-י-כ-ל-מ-נ-ס-ע-פ-צ-ק-ר-ש-ת"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "RUSSIAN",
            tokens = parseTokens("А-Б-В-Г-Д-Е-Ё-Ж-З-И-Й-К-Л-М-Н-О-П-Р-С-Т-У-Ф-Х-Ц-Ч-Ш-Щ-Ъ-Ы-Ь-Э-Ю-Я"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "CHINESE_BOPOMOFO",
            tokens = parseTokens("ㄅ-ㄆ-ㄇ-ㄈ-ㄉ-ㄊ-ㄋ-ㄌ-ㄍ-ㄎ-ㄏ-ㄐ-ㄑ-ㄒ-ㄓ-ㄔ-ㄕ-ㄖ-ㄗ-ㄘ-ㄙ-ㄚ-ㄛ-ㄜ-ㄝ-ㄞ-ㄟ-ㄠ-ㄡ-ㄢ-ㄣ-ㄤ-ㄥ-ㄦ-ㄧ-ㄨ-ㄩ"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "JAPANESE",
            tokens = parseTokens("あ-い-う-え-お-か-き-く-け-こ-さ-し-す-せ-そ-た-ち-つ-て-と-な-に-ぬ-ね-の-は-ひ-ふ-へ-ほ-ま-み-む-め-も-や-ゆ-よ-ら-り-る-れ-ろ-わ-を-ん"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "ENGLISH_UPPER",
            tokens = parseTokens("A-B-C-D-E-F-G-H-I-J-K-L-M-N-O-P-Q-R-S-T-U-V-W-X-Y-Z"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "ENGLISH_LOWER",
            tokens = parseTokens("a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v-w-x-y-z"),
            minimumPick = LANGUAGE_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "DIGITS",
            tokens = parseTokens("0-1-2-3-4-5-6-7-8-9"),
            minimumPick = DIGIT_MINIMUM_PICK
        ),
        ScriptGroup(
            name = "PUNCTUATION",
            tokens = listOf(
                '!', '@', '$', '%', '^', '&', '*', '(', ')',
                '_', '+', '=', '{', '}', '[', ']', '|',
                ':', ';', '"', '\'', '<', '>', ',', '.', '?', '/'
            ),
            minimumPick = PUNCTUATION_MINIMUM_PICK
        )
    )

    fun generate(length: Int = VaultConfig.AUTO_GENERATED_KEY_LENGTH): CharArray {
        val minLen = VaultConfig.MIN_AUTO_GENERATED_KEY_LENGTH
        val maxLen = VaultConfig.MAX_AUTO_GENERATED_KEY_LENGTH
        val targetLength = if (length in minLen..maxLen) length else minLen + rng.nextInt(maxLen - minLen + 1)

        val output = ArrayList<Char>(targetLength)

        for (group in scriptGroups) {
            repeat(group.minimumPick) {
                output.add(randomTokenFrom(group))
            }
        }

        val remaining = targetLength - output.size
        if (remaining > 0) {
            val extraGroups = buildDistributedRandomGroups(remaining)
            for (group in extraGroups) {
                output.add(randomTokenFrom(group))
            }
        }

        output.shuffle(rng)
        output.shuffle(rng)
        output.shuffle(rng)

        return output.take(targetLength).toCharArray()
    }

    private fun buildDistributedRandomGroups(count: Int): List<ScriptGroup> {
        val result = ArrayList<ScriptGroup>(count)

        while (result.size < count) {
            val round = scriptGroups.shuffled(rng)

            for (group in round) {
                if (result.size >= count) break
                result.add(group)
            }
        }

        result.shuffle(rng)
        return result
    }

    private fun randomTokenFrom(group: ScriptGroup): Char {
        return group.tokens[rng.nextInt(group.tokens.size)]
    }

    fun wipe(passphrase: CharArray?) {
        passphrase?.fill('\u0000')
    }
}

internal enum class FileStatus {
    ACTIVE,
    PENDING_DELETE
}

@Entity(tableName = "volatile_vault")
internal data class VaultEntity(
    @PrimaryKey val uuidHash: String,
    var status: String = FileStatus.ACTIVE.name,
    val createdAtEpochMs: Long = System.currentTimeMillis()
)

@Dao
internal interface VaultDao {
    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entity: VaultEntity)

    @Query("SELECT * FROM volatile_vault WHERE uuidHash = :hash LIMIT 1")
    suspend fun getByHash(hash: String): VaultEntity?

    @Query("SELECT * FROM volatile_vault WHERE status = 'PENDING_DELETE'")
    suspend fun getPendingDeletes(): List<VaultEntity>

    @Query("UPDATE volatile_vault SET status = :status WHERE uuidHash = :hash")
    suspend fun updateStatus(hash: String, status: String)

    @Query("DELETE FROM volatile_vault WHERE uuidHash = :hash")
    suspend fun deleteByHash(hash: String)

    @Transaction
    suspend fun markAsPending(hash: String) {
        updateStatus(hash, FileStatus.PENDING_DELETE.name)
    }
}

// =====================================================================
//  PHASE 3: Room Database Hardening (Secure Delete + Journal + WAL)
// =====================================================================

@Database(
    entities = [VaultEntity::class],
    version = VaultConfig.DB_VERSION,
    exportSchema = false
)
internal abstract class VolatileVaultDatabase : RoomDatabase() {

    abstract fun vaultDao(): VaultDao

    companion object {
        @Volatile
        private var INSTANCE: VolatileVaultDatabase? = null

        fun getInstance(context: Context): VolatileVaultDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    VolatileVaultDatabase::class.java,
                    VaultConfig.DB_NAME
                )
                    .setJournalMode(JournalMode.TRUNCATE)
                    .addCallback(object : Callback() {
                        override fun onOpen(db: SupportSQLiteDatabase) {
                            super.onOpen(db)
                            try {
                                db.execSQL(VaultConfig.PRAGMA_SECURE_DELETE)
                                db.execSQL(VaultConfig.PRAGMA_SYNCHRONOUS_FULL)
                                db.execSQL(VaultConfig.PRAGMA_WAL_CHECKPOINT_FULL)
                            } catch (_: Exception) { }
                        }

                        override fun onCreate(db: SupportSQLiteDatabase) {
                            super.onCreate(db)
                            try {
                                db.execSQL(VaultConfig.PRAGMA_SECURE_DELETE)
                                db.execSQL(VaultConfig.PRAGMA_SYNCHRONOUS_FULL)
                            } catch (_: Exception) { }
                        }
                    })
                    .fallbackToDestructiveMigration()
                    .build()

                INSTANCE = instance
                instance
            }
        }

        fun forceSecureCheckpointAndClose(context: Context) {
            INSTANCE?.let { db ->
                try {
                    val supportDb = db.openHelper.writableDatabase
                    supportDb.execSQL(VaultConfig.PRAGMA_WAL_CHECKPOINT_FULL)
                    supportDb.execSQL("PRAGMA wal_checkpoint(TRUNCATE)")
                    supportDb.close()
                } catch (_: Exception) { }

                try { db.close() } catch (_: Exception) { }
                INSTANCE = null
            }

            securelyWipeWALFiles(context)
        }

        private fun securelyWipeWALFiles(context: Context) {
            val dbPath = context.getDatabasePath(VaultConfig.DB_NAME)
            val walFile = File(dbPath.parentFile, "${VaultConfig.DB_NAME}-wal")
            val shmFile = File(dbPath.parentFile, "${VaultConfig.DB_NAME}-shm")

            listOf(walFile, shmFile).forEach { file ->
                if (file.exists() && file.isFile) {
                    try {
                        RandomAccessFile(file, "rws").use { raf ->
                            val len = file.length()
                            if (len > 0) {
                                val buf = ByteArray(minOf(65536, len.toInt()))
                                SecureRandom().nextBytes(buf)
                                raf.seek(0)
                                raf.write(buf)
                                raf.setLength(0)
                                raf.fd.sync()
                            }
                        }
                    } catch (_: Exception) { }
                    file.delete()
                }
            }
        }
    }
}

internal fun createHardenedVaultDao(context: Context): VaultDao {
    return VolatileVaultDatabase.getInstance(context).vaultDao()
}

internal object SecureErase {
    fun wipe(bytes: ByteArray?) {
        if (bytes == null) return
        if (bytes.isEmpty()) return
        bytes.fill(0)
        bytes[0].compareTo(0)
    }

    fun wipeChars(chars: CharArray?) {
        if (chars == null) return
        chars.fill('\u0000')
        if (chars.isNotEmpty()) {
            chars[0].compareTo('0')
        }
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    fun wipeKey(key: SecretKey?) {
        if (key is SecretKeySpec) {
            wipe(key.encoded)
        }
    }
}

internal class UuidObfuscator(private val masterKey: SecretKey) {
    private val hmacAlg = "HmacSHA256"

    fun hash(rawUuid: String): String {
        val mac = Mac.getInstance(hmacAlg)
        mac.init(masterKey)
        val hmacBytes = mac.doFinal(rawUuid.toByteArray(Charsets.UTF_8))
        return hmacBytes.joinToString("") { "%02x".format(it) }
    }

    fun resolvePendingFromDirectory(vaultDir: File, dao: VaultDao): List<Pair<String, String>> {
        if (!vaultDir.exists()) return emptyList()
        val result = mutableListOf<Pair<String, String>>()
        vaultDir.listFiles()?.forEach { file ->
            val name = file.nameWithoutExtension
            if (name.matches(Regex("^[0-9a-fA-F\\-]{36}$"))) {
                val h = hash(name)
                result.add(name to h)
            }
        }
        return result
    }
}

internal class NistPurgeEngine(private val rng: SecureRandom) {
    fun purge(file: File) {
        if (!file.exists() || !file.isFile) return

        try {
            val length = file.length()
            if (length == 0L) {
                file.delete()
                return
            }

            for (pass in VaultConfig.NIST_PURGE_PATTERNS) {
                RandomAccessFile(file, "rws").use { raf ->
                    val buf = ByteArray(minOf(
                        VaultConfig.OVERWRITE_BUFFER_SIZE,
                        (length.coerceAtMost(Int.MAX_VALUE.toLong())).toInt()
                    ))
                    var written = 0L
                    while (written < length) {
                        when (pass) {
                            PurgePassType.CRYPTO_RANDOM -> rng.nextBytes(buf)
                            PurgePassType.ALL_ZEROES -> buf.fill(0)
                            PurgePassType.ALL_ONES -> buf.fill(0xFF.toByte())
                        }
                        val toWrite = minOf(buf.size.toLong(), length - written).toInt()
                        raf.write(buf, 0, toWrite)
                        written += toWrite
                    }
                    raf.fd.sync()
                    SecureErase.wipe(buf)
                }
            }

            RandomAccessFile(file, "rws").use { raf ->
                raf.setLength(0L)
                raf.fd.sync()
            }

            val tmp = File(file.parentFile, ".vv_purge_${UUID.randomUUID()}")
            if (file.renameTo(tmp)) {
                tmp.delete()
            } else {
                file.delete()
            }

            file.parentFile?.let { parent ->
                try {
                    FileOutputStream(parent).fd.sync()
                } catch (_: Exception) {
                }
            }

            tryTriggerTrim(file, length)
        } catch (_: Exception) {
            try {
                file.delete()
            } catch (_: Exception) {
            }
        }
    }

    private fun tryTriggerTrim(deletedFile: File, originalLength: Long) {
        if (originalLength <= 0L) return
        try {
            val triggerFile = File(deletedFile.parentFile, ".vv_trim_${UUID.randomUUID()}")
            RandomAccessFile(triggerFile, "rws").use { raf ->
                raf.setLength(minOf(originalLength, 64L * 1024 * 1024))
                raf.fd.sync()
            }
            RandomAccessFile(triggerFile, "rws").use { raf ->
                val buf = ByteArray(4096)
                rng.nextBytes(buf)
                var written = 0L
                val len = triggerFile.length()
                while (written < len) {
                    val toWrite = minOf(buf.size.toLong(), len - written).toInt()
                    raf.write(buf, 0, toWrite)
                    written += toWrite
                }
                raf.fd.sync()
            }
            triggerFile.delete()
            triggerFile.parentFile?.let {
                try {
                    FileOutputStream(it).fd.sync()
                } catch (_: Exception) {
                }
            }
        } catch (_: Exception) {
        }
    }

    companion object {
        fun sanitizeOriginalFile(context: Context, originalUri: Uri) {
            try {
                val path = resolveDirectPath(context, originalUri)

                if (path != null) {
                    val file = File(path)
                    if (file.exists() && file.isFile) {
                        val engine = NistPurgeEngine(SecureRandom())
                        engine.purge(file)
                        MetadataSanitizer.sanitizeMediaStoreAfterDelete(context, file)
                        return
                    }
                }

                purgeUri(context, originalUri)
            } catch (_: Exception) {
            }
        }

        fun resolveDirectPathForSanitizer(context: Context, uri: Uri): String? {
            return resolveDirectPath(context, uri)
        }

        private fun purgeUri(context: Context, uri: Uri) {
            var descriptor: android.os.ParcelFileDescriptor? = null

            try {
                descriptor = try {
                    context.contentResolver.openFileDescriptor(uri, "rwt")
                } catch (_: Exception) {
                    null
                } ?: try {
                    context.contentResolver.openFileDescriptor(uri, "wt")
                } catch (_: Exception) {
                    null
                }

                val pfd = descriptor ?: return
                val size = pfd.statSize.takeIf { it > 0L } ?: 0L

                FileOutputStream(pfd.fileDescriptor).channel.use { channel ->
                    val random = SecureRandom()
                    val buffer = ByteArray(VaultConfig.OVERWRITE_BUFFER_SIZE)

                    if (size > 0L) {
                        repeat(3) { pass ->
                            channel.position(0L)
                            var written = 0L

                            while (written < size) {
                                when (pass) {
                                    0 -> random.nextBytes(buffer)
                                    1 -> buffer.fill(0)
                                    else -> buffer.fill(0xFF.toByte())
                                }

                                val toWrite = minOf(buffer.size.toLong(), size - written).toInt()
                                channel.write(ByteBuffer.wrap(buffer, 0, toWrite))
                                written += toWrite.toLong()
                            }

                            channel.force(true)
                        }
                    }

                    channel.truncate(0L)
                    channel.force(true)
                    SecureErase.wipe(buffer)
                }
            } catch (_: Exception) {
            } finally {
                try { descriptor?.close() } catch (_: Exception) { }
            }
        }

        private fun resolveDirectPath(context: Context, uri: Uri): String? {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                try {
                    val docId = DocumentsContract.getDocumentId(uri)
                    if (docId.startsWith("primary:")) {
                        return "/storage/emulated/0/" + docId.substringAfter("primary:")
                    }
                    val split = docId.split(":")
                    if (split.size >= 2) {
                        return "/storage/" + split[0] + "/" + split[1]
                    }
                } catch (_: Exception) {
                }
            }
            try {
                val cursor = context.contentResolver.query(
                    uri,
                    arrayOf(android.provider.MediaStore.MediaColumns.DATA),
                    null,
                    null,
                    null
                )
                cursor?.use {
                    if (it.moveToFirst()) {
                        val idx = it.getColumnIndex(android.provider.MediaStore.MediaColumns.DATA)
                        if (idx >= 0) return it.getString(idx)
                    }
                }
            } catch (_: Exception) {
            }
            return null
        }
    }
}

internal class VaultKeystore(
    private val masterAlias: String = "volatile_vault_master_aes_gcm_v3"
) {
    private val provider = "AndroidKeyStore"
    private val hmacAlias = "${masterAlias}_hmac"

    fun getOrCreateMasterKey(preferStrongBox: Boolean = true): SecretKey {
        val ks = KeyStore.getInstance(provider).apply { load(null) }
        ks.getKey(masterAlias, null)?.let { return it as SecretKey }

        val shouldRequestStrongBox = preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P

        return try {
            generateKey(masterAlias, useStrongBox = shouldRequestStrongBox)
        } catch (e: Exception) {
            val strongBoxUnavailable = shouldRequestStrongBox && isStrongBoxUnavailableException(e)
            if (strongBoxUnavailable || shouldRequestStrongBox) {
                generateKey(masterAlias, useStrongBox = false)
            } else {
                throw e
            }
        }
    }

    private fun isStrongBoxUnavailableException(error: Throwable): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return false
        return error.javaClass.name == "android.security.keystore.StrongBoxUnavailableException"
    }

    fun getOrCreateHmacKey(): SecretKey {
        val ks = KeyStore.getInstance(provider).apply { load(null) }
        ks.getKey(hmacAlias, null)?.let { return it as SecretKey }

        return try {
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, provider)
            val spec = KeyGenParameterSpec.Builder(
                hmacAlias,
                KeyProperties.PURPOSE_SIGN
            ).setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
            kg.init(spec)
            kg.generateKey()
        } catch (_: Exception) {
            val raw = ByteArray(32).also { SecureRandom().nextBytes(it) }
            SecretKeySpec(raw, "HmacSHA256")
        }
    }

    private fun generateKey(alias: String, useStrongBox: Boolean): SecretKey {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, provider)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(VaultConfig.AES_KEY_BITS)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        kg.init(builder.build())
        return kg.generateKey()
    }

    fun isHardwareBacked(): Boolean {
        return try {
            val ks = KeyStore.getInstance(provider).apply { load(null) }
            val key = ks.getKey(masterAlias, null) as? SecretKey ?: return false
            val factory = SecretKeyFactory.getInstance(key.algorithm, provider)
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            keyInfo.isInsideSecureHardware
        } catch (_: Exception) {
            false
        }
    }

    fun destroyMasterKey() {
        try {
            val ks = KeyStore.getInstance(provider).apply { load(null) }
            ks.deleteEntry(masterAlias)
            ks.deleteEntry(hmacAlias)
        } catch (_: Exception) {
        }
    }
}

internal object VaultCrypto {
    private const val AES_GCM = "AES/GCM/NoPadding"
    private const val PBKDF2 = "PBKDF2WithHmacSHA256"
    private const val AES = "AES"

    fun derivePassphraseKey(
        passphrase: CharArray,
        salt: ByteArray,
        iterations: Int = VaultConfig.PBKDF_ITERATIONS,
        keyBits: Int = VaultConfig.PBKDF_KEY_BITS,
        kdfType: Int = VaultConfig.KDF_TYPE_PBKDF2
    ): ByteArray {
        return when (kdfType) {
            VaultConfig.KDF_TYPE_ARGON2ID -> deriveArgon2idKey(passphrase, salt, keyBits)
            else -> derivePbkdf2Key(passphrase, salt, iterations, keyBits)
        }
    }

    private fun derivePbkdf2Key(
        passphrase: CharArray,
        salt: ByteArray,
        iterations: Int,
        keyBits: Int
    ): ByteArray {
        val spec = PBEKeySpec(passphrase, salt, iterations, keyBits)
        return try {
            SecretKeyFactory.getInstance(PBKDF2).generateSecret(spec).encoded
        } catch (e: InvalidKeySpecException) {
            throw IllegalStateException("PBKDF2 key derivation failed", e)
        } finally {
            spec.clearPassword()
        }
    }

    private fun deriveArgon2idKey(
        passphrase: CharArray,
        salt: ByteArray,
        keyBits: Int
    ): ByteArray {
        val argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id)
        return try {
            // Correct signature: hash(iterations, memory, parallelism, password: CharArray, charset: Charset)
            val hashResult = argon2.hash(
                VaultConfig.ARGON2_ITERATIONS,
                VaultConfig.ARGON2_MEMORY_KB,
                VaultConfig.ARGON2_PARALLELISM,
                passphrase,           // CharArray (exact match for library)
                Charsets.UTF_8
            )

            // Parse PHC format: $argon2id$v=19$m=16384,t=3,p=1$salt$hash
            val parts = hashResult.split("$")
            val encodedHash = if (parts.size >= 6) parts[5] else if (parts.size >= 5) parts.last() else hashResult

            val rawKey = try {
                java.util.Base64.getDecoder().decode(encodedHash)
            } catch (e: Exception) {
                decodeArgon2Base64(encodedHash)
            }

            val targetLen = keyBits / 8
            when {
                rawKey.size == targetLen -> rawKey
                rawKey.size > targetLen -> rawKey.copyOf(targetLen)
                else -> {
                    val padded = ByteArray(targetLen)
                    System.arraycopy(rawKey, 0, padded, 0, rawKey.size)
                    padded
                }
            }
        } finally {
            argon2.wipeArray(passphrase)
        }
    }

    /**
     * Fallback decoder for argon2 modified Base64
     */
    private fun decodeArgon2Base64(input: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val map = IntArray(128) { -1 }
        for (i in alphabet.indices) {
            map[alphabet[i].code] = i
        }

        val len = input.length
        var padding = 0
        if (len > 0 && input[len - 1] == '=') padding++
        if (len > 1 && input[len - 2] == '=') padding++

        val out = ByteArray(len * 3 / 4 - padding)
        var i = 0
        var j = 0

        while (i < len - padding) {
            val a = map[input[i++].code]
            val b = map[input[i++].code]
            val c = if (i < len) map[input[i++].code] else 0
            val d = if (i < len) map[input[i++].code] else 0

            val triple = (a shl 18) or (b shl 12) or ((c and 0x3F) shl 6) or (d and 0x3F)

            out[j++] = ((triple shr 16) and 0xFF).toByte()
            if (j < out.size) out[j++] = ((triple shr 8) and 0xFF).toByte()
            if (j < out.size) out[j++] = (triple and 0xFF).toByte()
        }
        return out
    }

    fun aesGcmEncrypt(
        keyBytes: ByteArray,
        iv: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, AES), GCMParameterSpec(VaultConfig.AES_GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun aesGcmDecrypt(
        keyBytes: ByteArray,
        iv: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, AES), GCMParameterSpec(VaultConfig.AES_GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    fun keystoreEncrypt(
        masterKey: SecretKey,
        plaintext: ByteArray,
        aad: ByteArray? = null
    ): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.ENCRYPT_MODE, masterKey)
        if (aad != null) cipher.updateAAD(aad)
        val ct = cipher.doFinal(plaintext)
        return cipher.iv to ct
    }

    fun keystoreDecrypt(
        masterKey: SecretKey,
        iv: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray? = null
    ): ByteArray {
        val cipher = Cipher.getInstance(AES_GCM)
        cipher.init(Cipher.DECRYPT_MODE, masterKey, GCMParameterSpec(VaultConfig.AES_GCM_TAG_BITS, iv))
        if (aad != null) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    fun makeChunkIv(prefix8: ByteArray, chunkIndex: Int): ByteArray {
        require(prefix8.size == VaultConfig.CHUNK_IV_PREFIX_BYTES) {
            "IV prefix must be exactly ${VaultConfig.CHUNK_IV_PREFIX_BYTES} bytes"
        }
        val iv = ByteArray(VaultConfig.GCM_NONCE_BYTES)
        System.arraycopy(prefix8, 0, iv, 0, VaultConfig.CHUNK_IV_PREFIX_BYTES)
        iv[8] = ((chunkIndex ushr 24) and 0xFF).toByte()
        iv[9] = ((chunkIndex ushr 16) and 0xFF).toByte()
        iv[10] = ((chunkIndex ushr 8) and 0xFF).toByte()
        iv[11] = (chunkIndex and 0xFF).toByte()
        return iv
    }

    fun aadForChunk(uuid: String, chunkIndex: Int): ByteArray =
        "VVv3-CHUNK|$uuid|$chunkIndex".toByteArray(Charsets.UTF_8)

    fun aadForKeyRecord(uuid: String): ByteArray =
        "VVv3-KEYREC|$uuid".toByteArray(Charsets.UTF_8)

    fun aadForDekWrap(uuid: String): ByteArray =
        "VVv3-DEKWRAP|$uuid".toByteArray(Charsets.UTF_8)
}

internal object MetadataSanitizer {
    fun sweepAppCaches(context: Context, uuid: String) {
        val dirs = listOfNotNull(
            context.cacheDir,
            context.codeCacheDir,
            context.externalCacheDir
        )
        for (dir in dirs) {
            try {
                if (!dir.exists()) continue
                dir.walkBottomUp().forEach { file ->
                    if (file.isFile && (
                                file.name.contains(uuid, ignoreCase = true) ||
                                        file.name.contains("thumb", ignoreCase = true) ||
                                        file.name.endsWith(".tmp")
                                )
                    ) {
                        try {
                            RandomAccessFile(file, "rws").use { raf ->
                                val len = file.length().coerceAtMost(1_048_576)
                                if (len > 0) {
                                    val buf = ByteArray(len.toInt())
                                    SecureRandom().nextBytes(buf)
                                    raf.write(buf)
                                    raf.fd.sync()
                                    SecureErase.wipe(buf)
                                }
                                raf.setLength(0)
                                raf.fd.sync()
                            }
                        } catch (_: Exception) {
                        }
                        file.delete()
                    }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun sanitizeMediaStoreAfterDelete(context: Context, file: File) {
        try {
            removeMediaStoreRowsByPath(context, file.absolutePath)
        } catch (_: Exception) {
        }

        try {
            MediaScannerConnection.scanFile(
                context,
                arrayOf(file.absolutePath, file.parentFile?.absolutePath ?: file.absolutePath),
                null,
                null
            )
        } catch (_: Exception) {
        }

        try {
            sweepKnownThumbnailCaches(context, file)
        } catch (_: Exception) {
        }
    }

    private fun removeMediaStoreRowsByPath(context: Context, absolutePath: String) {
        val resolver = context.contentResolver
        val collection = MediaStore.Files.getContentUri("external")

        try {
            resolver.delete(
                collection,
                "${MediaStore.MediaColumns.DATA}=?",
                arrayOf(absolutePath)
            )
        } catch (_: Exception) {
        }
    }

    private fun sweepKnownThumbnailCaches(context: Context, deletedFile: File) {
        val parentModified = deletedFile.lastModified()
        val lowerName = deletedFile.name.lowercase(Locale.getDefault())
        val isLikelyMedia = lowerName.endsWith(".jpg") ||
                lowerName.endsWith(".jpeg") ||
                lowerName.endsWith(".png") ||
                lowerName.endsWith(".webp") ||
                lowerName.endsWith(".heic") ||
                lowerName.endsWith(".heif") ||
                lowerName.endsWith(".mp4") ||
                lowerName.endsWith(".mkv") ||
                lowerName.endsWith(".mov")

        if (!isLikelyMedia) return

        val root = Environment.getExternalStorageDirectory()
        val candidates = listOfNotNull(
            File(root, "DCIM/.thumbnails"),
            File(root, "Pictures/.thumbnails"),
            File(root, "Movies/.thumbnails"),
            context.cacheDir,
            context.externalCacheDir
        )

        var inspected = 0
        val maxInspect = 300
        val maxThumbSize = 8L * 1024L * 1024L
        val timeWindowMs = 24L * 60L * 60L * 1000L

        for (dir in candidates) {
            if (!dir.exists() || !dir.isDirectory) continue

            try {
                dir.walkTopDown().forEach { item ->
                    if (inspected >= maxInspect) return@forEach
                    if (!item.isFile) return@forEach

                    inspected++

                    val nearTime = kotlin.math.abs(item.lastModified() - parentModified) <= timeWindowMs
                    val smallEnough = item.length() in 1L..maxThumbSize
                    val nameLooksCached = item.name.contains("thumb", ignoreCase = true) ||
                            item.name.endsWith(".jpg", ignoreCase = true) ||
                            item.name.endsWith(".png", ignoreCase = true) ||
                            item.name.endsWith(".webp", ignoreCase = true)

                    if (nearTime && smallEnough && nameLooksCached) {
                        try {
                            NistPurgeEngine(SecureRandom()).purge(item)
                        } catch (_: Exception) {
                            try { item.delete() } catch (_: Exception) { }
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
    }

    fun boundedCacheEviction(directory: File?, maxBytes: Long = VaultConfig.BOUNDED_CACHE_EVICTION_MAX_BYTES) {
        val dir = directory ?: return
        if (!dir.exists() || !dir.isDirectory) return
        if (maxBytes <= 0L) return

        val tempFile = File(dir, ".vv_cache_evict_${UUID.randomUUID()}")
        val buffer = ByteArray(VaultConfig.OVERWRITE_BUFFER_SIZE)
        val random = SecureRandom()
        var written = 0L

        try {
            FileOutputStream(tempFile).use { output ->
                while (written < maxBytes) {
                    random.nextBytes(buffer)
                    val toWrite = minOf(buffer.size.toLong(), maxBytes - written).toInt()
                    output.write(buffer, 0, toWrite)
                    written += toWrite.toLong()
                }
                output.fd.sync()
            }
        } catch (_: Exception) {
        } finally {
            SecureErase.wipe(buffer)
            try { tempFile.delete() } catch (_: Exception) { }
        }
    }

    fun deleteOriginalFile(context: Context, originalUri: Uri?) {
        if (originalUri == null) return

        val directPath = try {
            NistPurgeEngine.resolveDirectPathForSanitizer(context, originalUri)
        } catch (_: Exception) {
            null
        }

        try {
            NistPurgeEngine.sanitizeOriginalFile(context, originalUri)
        } catch (_: Exception) {
        }

        try {
            if (
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT &&
                DocumentsContract.isDocumentUri(context, originalUri)
            ) {
                DocumentsContract.deleteDocument(context.contentResolver, originalUri)
            } else {
                context.contentResolver.delete(originalUri, null, null)
            }
        } catch (_: Exception) {
        }

        if (directPath != null) {
            sanitizeMediaStoreAfterDelete(context, File(directPath))
        }
    }

    fun syncDirectory(dir: File) {
        try {
            FileOutputStream(dir).fd.sync()
        } catch (_: Exception) {
        }
    }
}

private val DATA_MAGIC = byteArrayOf('V'.code.toByte(), 'V'.code.toByte(), 'C'.code.toByte(), 'T'.code.toByte())
private val KEY_MAGIC = byteArrayOf('V'.code.toByte(), 'V'.code.toByte(), 'K'.code.toByte(), 'R'.code.toByte())
private val KEYSTORE_BLOB_MAGIC = byteArrayOf('V'.code.toByte(), 'V'.code.toByte(), 'K'.code.toByte(), 'S'.code.toByte())

internal class VolatileVaultEngine(
    private val context: Context,
    private val dao: VaultDao,
    private val preferStrongBox: Boolean = true,
    private val pbkdfIterations: Int = VaultConfig.PBKDF_ITERATIONS
) {
    private val rng = SecureRandom()
    private val keystore = VaultKeystore()
    private val purgeEngine = NistPurgeEngine(rng)

    private val vaultDir: File =
        File(context.noBackupFilesDir, "vv_ciphertexts_v3").apply { mkdirs() }

    private val keyDir: File =
        File(context.noBackupFilesDir, "vv_keyrecords_v3").apply { mkdirs() }

    private val chunkSize: Int by lazy {
        val memMb = (Runtime.getRuntime().maxMemory() / (1024 * 1024))
        if (memMb <= VaultConfig.LOW_RAM_THRESHOLD_MB) {
            VaultConfig.BASE_CHUNK_SIZE
        } else {
            VaultConfig.STANDARD_CHUNK_SIZE
        }
    }

    suspend fun ingestFile(
        inputStream: InputStream,
        passphrase: CharArray,
        originalUri: Uri? = null,
        deleteOriginal: Boolean = true
    ): String = withContext(Dispatchers.IO) {
        requireStrongPassphrase(passphrase)

        val uuid = UUID.randomUUID().toString()
        val dataFile = vaultFile(uuid)
        val keyFile = keyRecordFile(uuid)

        var dek: ByteArray? = null
        var passKey: ByteArray? = null
        var keyRecordPlain: ByteArray? = null

        try {
            dek = ByteArray(32).also { rng.nextBytes(it) }
            writeEncryptedData(uuid, inputStream, dataFile, dek)

            val salt = ByteArray(VaultConfig.SALT_BYTES).also { rng.nextBytes(it) }
            passKey = VaultCrypto.derivePassphraseKey(
                passphrase = passphrase,
                salt = salt,
                iterations = pbkdfIterations
            )

            val wrapIv = ByteArray(VaultConfig.GCM_NONCE_BYTES).also { rng.nextBytes(it) }
            val wrappedDek = VaultCrypto.aesGcmEncrypt(
                keyBytes = passKey!!,
                iv = wrapIv,
                plaintext = dek!!,
                aad = VaultCrypto.aadForDekWrap(uuid)
            )

            keyRecordPlain = buildKeyRecord(salt, pbkdfIterations, wrapIv, wrappedDek, VaultConfig.KDF_TYPE_PBKDF2)
            writeKeystoreWrappedKeyRecord(uuid, keyRecordPlain!!, keyFile)

            val obfuscator = UuidObfuscator(keystore.getOrCreateMasterKey(preferStrongBox))
            dao.insert(VaultEntity(uuidHash = obfuscator.hash(uuid)))

            if (deleteOriginal) {
                MetadataSanitizer.deleteOriginalFile(context, originalUri)
            }

            uuid
        } catch (e: Exception) {
            purgeEngine.purge(keyFile)
            purgeEngine.purge(dataFile)
            throw e
        } finally {
            SecureErase.wipe(dek)
            SecureErase.wipe(passKey)
            SecureErase.wipe(keyRecordPlain)
            MultiScriptPassphraseGenerator.wipe(passphrase)
            try {
                inputStream.close()
            } catch (_: Exception) {
            }
        }
    }

    suspend fun autoIngestFile(
        inputStream: InputStream,
        originalUri: Uri? = null,
        deleteOriginal: Boolean = true
    ): Pair<String, CharArray> = withContext(Dispatchers.IO) {
        val passphrase = MultiScriptPassphraseGenerator.generate()
        val uuid = ingestFile(
            inputStream = inputStream,
            passphrase = passphrase,
            originalUri = originalUri,
            deleteOriginal = deleteOriginal
        )
        uuid to passphrase
    }

    private fun writeEncryptedData(
        uuid: String,
        inputStream: InputStream,
        outFile: File,
        dek: ByteArray
    ) {
        val noncePrefix = ByteArray(VaultConfig.CHUNK_IV_PREFIX_BYTES).also { rng.nextBytes(it) }

        BufferedInputStream(inputStream, chunkSize).use { bis ->
            DataOutputStream(BufferedOutputStream(FileOutputStream(outFile), chunkSize)).use { dos ->
                dos.write(DATA_MAGIC)
                dos.writeInt(VaultConfig.FORMAT_VERSION)
                dos.writeInt(chunkSize)
                dos.writeInt(noncePrefix.size)
                dos.write(noncePrefix)

                val plainBuf = ByteArray(chunkSize)
                var chunkIndex = 0

                while (true) {
                    val bytesRead = bis.read(plainBuf)
                    if (bytesRead == -1) break

                    if (chunkIndex == Int.MAX_VALUE) {
                        throw IllegalStateException("File exceeds maximum supported size")
                    }

                    val plainChunk = if (bytesRead == plainBuf.size) plainBuf else plainBuf.copyOf(bytesRead)
                    val iv = VaultCrypto.makeChunkIv(noncePrefix, chunkIndex)
                    val aad = VaultCrypto.aadForChunk(uuid, chunkIndex)

                    val cipherChunk = VaultCrypto.aesGcmEncrypt(
                        keyBytes = dek,
                        iv = iv,
                        plaintext = plainChunk,
                        aad = aad
                    )

                    dos.writeInt(cipherChunk.size)
                    dos.write(cipherChunk)

                    if (plainChunk !== plainBuf) SecureErase.wipe(plainChunk)
                    SecureErase.wipe(cipherChunk)
                    chunkIndex++
                }

                SecureErase.wipe(plainBuf)
                dos.flush()
            }
        }

        FileOutputStream(outFile, true).use { it.fd.sync() }
        MetadataSanitizer.syncDirectory(outFile.parentFile!!)
    }

    private fun buildKeyRecord(
        salt: ByteArray,
        iterations: Int,
        wrapIv: ByteArray,
        wrappedDek: ByteArray,
        kdfType: Int = VaultConfig.KDF_TYPE_PBKDF2
    ): ByteArray {
        ByteArrayOutputStream().use { baos ->
            DataOutputStream(baos).use { dos ->
                dos.write(KEY_MAGIC)
                dos.writeInt(VaultConfig.FORMAT_VERSION)
                dos.writeInt(kdfType)
                dos.writeInt(iterations)
                dos.writeInt(salt.size)
                dos.write(salt)
                dos.writeInt(wrapIv.size)
                dos.write(wrapIv)
                dos.writeInt(wrappedDek.size)
                dos.write(wrappedDek)
            }
            return baos.toByteArray()
        }
    }

    private fun writeKeystoreWrappedKeyRecord(
        uuid: String,
        keyRecordPlain: ByteArray,
        outFile: File
    ) {
        val masterKey = keystore.getOrCreateMasterKey(preferStrongBox)
        val aad = VaultCrypto.aadForKeyRecord(uuid)

        val (keystoreIv, keystoreCt) = VaultCrypto.keystoreEncrypt(
            masterKey = masterKey,
            plaintext = keyRecordPlain,
            aad = aad
        )

        DataOutputStream(BufferedOutputStream(FileOutputStream(outFile))).use { dos ->
            dos.write(KEYSTORE_BLOB_MAGIC)
            dos.writeInt(VaultConfig.FORMAT_VERSION)
            dos.writeInt(keystoreIv.size)
            dos.write(keystoreIv)
            dos.writeInt(keystoreCt.size)
            dos.write(keystoreCt)
            dos.flush()
        }

        FileOutputStream(outFile, true).use { it.fd.sync() }
        MetadataSanitizer.syncDirectory(outFile.parentFile!!)
        SecureErase.wipe(keystoreCt)
    }

    suspend fun shredFile(uuid: String) = withContext(Dispatchers.IO) {
        val obfuscator = UuidObfuscator(keystore.getOrCreateMasterKey(preferStrongBox))
        val hash = obfuscator.hash(uuid)
        dao.getByHash(hash) ?: return@withContext

        dao.markAsPending(hash)

        val dataFile = vaultFile(uuid)
        val keyFile = keyRecordFile(uuid)

        purgeEngine.purge(keyFile)
        purgeEngine.purge(dataFile)

        MetadataSanitizer.sweepAppCaches(context, uuid)
        MetadataSanitizer.boundedCacheEviction(vaultDir.parentFile)
        MetadataSanitizer.syncDirectory(vaultDir)
        MetadataSanitizer.syncDirectory(keyDir)
        dao.deleteByHash(hash)
    }

    suspend fun resumePendingDeletions() = withContext(Dispatchers.IO) {
        val obfuscator = UuidObfuscator(keystore.getOrCreateMasterKey(preferStrongBox))
        val pending = dao.getPendingDeletes()

        if (pending.isNotEmpty()) {
            val uuidSet = mutableSetOf<String>()
            vaultDir.listFiles()?.forEach { file ->
                val name = file.nameWithoutExtension
                if (name.matches(Regex("^[0-9a-fA-F\\-]{36}$"))) {
                    uuidSet.add(name)
                }
            }

            for (entity in pending) {
                val match = uuidSet.firstOrNull { obfuscator.hash(it) == entity.uuidHash }
                if (match != null) {
                    shredFile(match)
                } else {
                    dao.deleteByHash(entity.uuidHash)
                }
            }
        }
    }

    suspend fun destroyVault() = withContext(Dispatchers.IO) {
        dao.getPendingDeletes()
        try {
            vaultDir.listFiles()?.forEach { file ->
                val name = file.nameWithoutExtension
                if (name.matches(Regex("^[0-9a-fA-F\\-]{36}$"))) {
                    shredFile(name)
                }
            }
        } catch (_: Exception) {
        }

        keystore.destroyMasterKey()

        try {
            VolatileVaultDatabase.forceSecureCheckpointAndClose(context)
        } catch (_: Exception) {
        }

        try {
            context.deleteDatabase(VaultConfig.DB_NAME)
        } catch (_: Exception) {
        }

        vaultDir.listFiles()?.forEach { purgeEngine.purge(it) }
        keyDir.listFiles()?.forEach { purgeEngine.purge(it) }

        MetadataSanitizer.syncDirectory(vaultDir)
        MetadataSanitizer.syncDirectory(keyDir)
        MetadataSanitizer.syncDirectory(vaultDir.parentFile!!)
    }

    suspend fun secureClose() = withContext(Dispatchers.IO) {
        try {
            VolatileVaultDatabase.forceSecureCheckpointAndClose(context)
        } catch (_: Exception) { }
    }

    fun recoverDek(uuid: String, passphrase: CharArray): ByteArray {
        val keyFile = keyRecordFile(uuid)
        require(keyFile.exists()) { "Key record not found for UUID: $uuid" }

        val masterKey = keystore.getOrCreateMasterKey(preferStrongBox)
        val aad = VaultCrypto.aadForKeyRecord(uuid)

        val keyRecordPlain = readKeystoreWrappedRecord(uuid, masterKey, keyFile, aad)
        var passKey: ByteArray? = null

        try {
            DataInputStream(keyRecordPlain.inputStream()).use { dis ->
                val magic = ByteArray(4)
                dis.readFully(magic)
                require(SecureErase.constantTimeEquals(magic, KEY_MAGIC)) { "Invalid key record magic" }

                val version = dis.readInt()
                require(version <= VaultConfig.FORMAT_VERSION) { "Unsupported key record version: $version" }

                val kdfType = if (version >= 4) dis.readInt() else VaultConfig.KDF_TYPE_PBKDF2
                val iterations = dis.readInt()
                val saltLen = dis.readInt()
                require(saltLen in 16..128)
                val salt = ByteArray(saltLen)
                dis.readFully(salt)

                val ivLen = dis.readInt()
                require(ivLen == VaultConfig.GCM_NONCE_BYTES)
                val iv = ByteArray(ivLen)
                dis.readFully(iv)

                val wrappedLen = dis.readInt()
                require(wrappedLen in 48..4096)
                val wrappedDek = ByteArray(wrappedLen)
                dis.readFully(wrappedDek)

                passKey = VaultCrypto.derivePassphraseKey(passphrase, salt, iterations, VaultConfig.PBKDF_KEY_BITS, kdfType)

                return VaultCrypto.aesGcmDecrypt(
                    keyBytes = passKey!!,
                    iv = iv,
                    ciphertext = wrappedDek,
                    aad = VaultCrypto.aadForDekWrap(uuid)
                )
            }
        } finally {
            SecureErase.wipe(passKey)
            SecureErase.wipe(keyRecordPlain)
            SecureErase.wipeChars(passphrase)
        }
    }

    private fun readKeystoreWrappedRecord(
        uuid: String,
        masterKey: SecretKey,
        keyFile: File,
        aad: ByteArray
    ): ByteArray {
        DataInputStream(BufferedInputStream(FileInputStream(keyFile))).use { dis ->
            val magic = ByteArray(4)
            dis.readFully(magic)
            require(SecureErase.constantTimeEquals(magic, KEYSTORE_BLOB_MAGIC)) { "Invalid keystore blob magic" }

            val version = dis.readInt()
            require(version <= VaultConfig.FORMAT_VERSION) { "Unsupported keystore blob version" }

            val ivLen = dis.readInt()
            require(ivLen == VaultConfig.GCM_NONCE_BYTES)
            val iv = ByteArray(ivLen)
            dis.readFully(iv)

            val ctLen = dis.readInt()
            require(ctLen in 32..65536)
            val ct = ByteArray(ctLen)
            dis.readFully(ct)

            return VaultCrypto.keystoreDecrypt(masterKey, iv, ct, aad)
        }
    }

    fun isStrongBoxBacked(): Boolean {
        keystore.getOrCreateMasterKey(preferStrongBox)
        return keystore.isHardwareBacked()
    }

    private fun vaultFile(uuid: String): File {
        validateUuid(uuid)
        return File(vaultDir, "$uuid.vvct")
    }

    private fun keyRecordFile(uuid: String): File {
        validateUuid(uuid)
        return File(keyDir, "$uuid.vvkr")
    }

    private fun validateUuid(uuid: String) {
        require(uuid.matches(Regex("^[0-9a-fA-F\\-]{36}$"))) {
            "Invalid UUID format: $uuid"
        }
    }

    private fun requireStrongPassphrase(passphrase: CharArray) {
        require(passphrase.size >= 20) {
            "Passphrase too weak: minimum 20 characters required. Use " +
                    VaultConfig.MIN_AUTO_GENERATED_KEY_LENGTH + "–" + VaultConfig.MAX_AUTO_GENERATED_KEY_LENGTH + " char auto-generated key for maximum security."
        }

        val hasLower = passphrase.any { it.isLowerCase() }
        val hasUpper = passphrase.any { it.isUpperCase() }
        val hasDigit = passphrase.any { it.isDigit() }
        val hasSymbol = passphrase.any { !it.isLetterOrDigit() }

        require(listOf(hasLower, hasUpper, hasDigit, hasSymbol).count { it } >= 3) {
            "Passphrase too weak: must contain at least 3 of: lowercase, uppercase, digits, symbols."
        }
    }
}

// =====================================================================
//  PHASE 3: PUBLIC HELPERS FOR SECURE DB INITIALIZATION (Recommended Usage)
// =====================================================================

internal fun getSecureVaultDao(context: Context): VaultDao {
    return createHardenedVaultDao(context)
}

internal fun createSecureVolatileVaultEngine(
    context: Context,
    preferStrongBox: Boolean = true,
    pbkdfIterations: Int = VaultConfig.PBKDF_ITERATIONS
): VolatileVaultEngine {
    val dao = getSecureVaultDao(context)
    return VolatileVaultEngine(
        context = context,
        dao = dao,
        preferStrongBox = preferStrongBox,
        pbkdfIterations = pbkdfIterations
    )
}
