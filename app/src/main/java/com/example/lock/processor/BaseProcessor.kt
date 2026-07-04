package com.example.lock.processor

import android.content.Context
import com.example.lock.crypto.EncryptionManager
import java.io.File
import java.io.RandomAccessFile
import java.security.SecureRandom
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

abstract class BaseProcessor(protected val context: Context) {

    companion object {
        protected const val STORAGE_BUFFER_SIZE = 65536
        private const val TEMP_DOUBLE_ZIP_FILE_NAME = "temp_double_wrapper.zip"
        private const val DOUBLE_ZIP_METADATA_MARKER = "DOUBLE_ZIP_PACKAGE"
    }

    protected fun createZip(files: List<File>, zipFile: File) {
        if (zipFile.exists()) {
            secureDelete(zipFile)
        }

        ZipOutputStream(zipFile.outputStream().buffered(STORAGE_BUFFER_SIZE)).use { zipOut ->
            val buffer = ByteArray(STORAGE_BUFFER_SIZE)

            for (file in files) {
                if (file.exists() && file.isFile) {
                    val entry = ZipEntry(file.name)
                    zipOut.putNextEntry(entry)

                    file.inputStream().buffered(STORAGE_BUFFER_SIZE).use { input ->
                        var bytesRead: Int

                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            zipOut.write(buffer, 0, bytesRead)
                        }
                    }

                    zipOut.closeEntry()
                }
            }

            zipOut.flush()
        }
    }

    protected fun runEncryption(
        inputFile: File,
        outputDirectory: File,
        password: CharArray,
        metadata: ByteArray = ByteArray(0),
        originalFileName: String = inputFile.name,
        onProgress: ((EncryptionManager.ProgressSnapshot) -> Unit)? = null
    ): File {
        val manager = EncryptionManager()
        val passwordCopy = password.copyOf()

        return manager.encryptFile(
            inputFile = inputFile,
            outputDirectory = outputDirectory,
            password = passwordCopy,
            onProgress = onProgress
        )
    }

    protected fun applyDoubleEncryption(
        encryptedFile: File,
        secondLayerPassword: CharArray,
        finalOutputDirectory: File,
        onProgress: ((EncryptionManager.ProgressSnapshot) -> Unit)? = null
    ): File {
        val tempZip = File(context.cacheDir, TEMP_DOUBLE_ZIP_FILE_NAME)

        try {
            createZip(listOf(encryptedFile), tempZip)

            return runEncryption(
                inputFile = tempZip,
                outputDirectory = finalOutputDirectory,
                password = secondLayerPassword,
                metadata = DOUBLE_ZIP_METADATA_MARKER.toByteArray(Charsets.UTF_8),
                originalFileName = tempZip.name,
                onProgress = onProgress
            )
        } finally {
            secureDelete(tempZip)
        }
    }

    protected fun resolveSecondLayerPassword(
        primaryPassword: CharArray,
        secondZipPassword: CharArray?
    ): CharArray {
        return if (secondZipPassword == null || secondZipPassword.isEmpty()) {
            primaryPassword
        } else {
            secondZipPassword
        }
    }

    protected fun secureDelete(file: File) {
        if (!file.exists()) return

        try {
            if (file.isFile) {
                val length = file.length()

                if (length > 0) {
                    RandomAccessFile(file, "rws").use { raf ->
                        val buffer = ByteArray(STORAGE_BUFFER_SIZE)
                        val secureRandom = SecureRandom()
                        var remaining = length

                        while (remaining > 0) {
                            secureRandom.nextBytes(buffer)

                            val toWrite = minOf(
                                remaining,
                                buffer.size.toLong()
                            ).toInt()

                            raf.write(buffer, 0, toWrite)
                            remaining -= toWrite
                        }
                    }
                }

                file.delete()
            }
        } catch (_: Exception) {
            file.delete()
        }
    }
}