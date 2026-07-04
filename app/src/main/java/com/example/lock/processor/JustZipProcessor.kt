package com.example.lock.processor

import android.content.Context
import com.example.lock.crypto.EncryptionManager
import java.io.File

class JustZipProcessor(context: Context) : BaseProcessor(context) {

    companion object {
        const val TEMPORARY_PLAINTEXT_ZIP = "raw_payload_archive.zip"
    }

    fun process(
        files: List<File>,
        password: CharArray,
        outputDirectory: File,
        deleteAfterEncryption: Boolean,
        doubleZip: Boolean,
        secondZipPassword: CharArray? = null,
        onProgress: ((EncryptionManager.ProgressSnapshot, String) -> Unit)? = null
    ) {
        val validFiles = files.filter { it.exists() && it.isFile }
        val tempZipFile = File(context.cacheDir, TEMPORARY_PLAINTEXT_ZIP)

        var outputFile: File? = null
        var tempFirstLayerEnc: File? = null

        try {
            if (validFiles.isEmpty()) return

            onProgress?.invoke(
                EncryptionManager.ProgressSnapshot(
                    processedBytes = 0,
                    totalBytes = 100
                ),
                "Creating zip package..."
            )

            createZip(validFiles, tempZipFile)

            outputFile = if (!doubleZip) {
                runEncryption(
                    inputFile = tempZipFile,
                    outputDirectory = outputDirectory,
                    password = password,
                    originalFileName = tempZipFile.name,
                    onProgress = { snapshot ->
                        onProgress?.invoke(snapshot, "Encrypting zip package... ${snapshot.percent}%")
                    }
                )
            } else {
                val secondLayerPassword = resolveSecondLayerPassword(
                    primaryPassword = password,
                    secondZipPassword = secondZipPassword
                )

                tempFirstLayerEnc = runEncryption(
                    inputFile = tempZipFile,
                    outputDirectory = context.cacheDir,
                    password = password,
                    originalFileName = tempZipFile.name,
                    onProgress = { snapshot ->
                        val overall = (snapshot.percent / 2).coerceIn(0, 100)

                        onProgress?.invoke(
                            EncryptionManager.ProgressSnapshot(
                                processedBytes = overall.toLong(),
                                totalBytes = 100L
                            ),
                            "Encrypting first layer... ${snapshot.percent}%"
                        )
                    }
                )

                applyDoubleEncryption(
                    encryptedFile = tempFirstLayerEnc!!,
                    secondLayerPassword = secondLayerPassword,
                    finalOutputDirectory = outputDirectory,
                    onProgress = { snapshot ->
                        val overall = (50 + (snapshot.percent / 2)).coerceIn(0, 100)

                        onProgress?.invoke(
                            EncryptionManager.ProgressSnapshot(
                                processedBytes = overall.toLong(),
                                totalBytes = 100L
                            ),
                            "Encrypting second layer... ${snapshot.percent}%"
                        )
                    }
                )
            }

            onProgress?.invoke(
                EncryptionManager.ProgressSnapshot(
                    processedBytes = 100,
                    totalBytes = 100
                ),
                "Encryption completed"
            )

            if (deleteAfterEncryption) {
                for (file in validFiles) {
                    secureDelete(file)
                }
            }
        } catch (e: Exception) {
            outputFile?.let {
                if (it.exists()) secureDelete(it)
            }
            throw e
        } finally {
            secureDelete(tempZipFile)

            tempFirstLayerEnc?.let {
                if (it.exists()) secureDelete(it)
            }
        }
    }
}