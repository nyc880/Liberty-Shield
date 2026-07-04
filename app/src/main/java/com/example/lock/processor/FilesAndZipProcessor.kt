package com.example.lock.processor

import android.content.Context
import com.example.lock.crypto.EncryptionManager
import java.io.File

class FilesAndZipProcessor(context: Context) : BaseProcessor(context) {

    companion object {
        const val RAW_ZIP_CONTAINER_NAME = "nested_container.zip"
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
        val totalFiles = validFiles.size

        val tempEncFiles = ArrayList<File>()
        val tempRawZip = File(context.cacheDir, RAW_ZIP_CONTAINER_NAME)

        var tempFirstLayerEnc: File? = null
        var outputFile: File? = null

        try {
            if (validFiles.isEmpty()) return

            for ((index, file) in validFiles.withIndex()) {
                val tempEncFile = runEncryption(
                    inputFile = file,
                    outputDirectory = context.cacheDir,
                    password = password,
                    onProgress = { snapshot ->
                        val phasePercent =
                            if (totalFiles == 0) {
                                0
                            } else {
                                ((index * 50) / totalFiles) + (snapshot.percent / (2 * totalFiles))
                            }

                        onProgress?.invoke(
                            EncryptionManager.ProgressSnapshot(
                                processedBytes = phasePercent.coerceIn(0, 100).toLong(),
                                totalBytes = 100L
                            ),
                            "Encrypting ${file.name}... ${snapshot.percent}%"
                        )
                    }
                )

                tempEncFiles.add(tempEncFile)
            }

            if (tempEncFiles.isEmpty()) return

            onProgress?.invoke(
                EncryptionManager.ProgressSnapshot(
                    processedBytes = 50,
                    totalBytes = 100
                ),
                "Creating encrypted zip container..."
            )

            createZip(tempEncFiles, tempRawZip)

            outputFile = if (!doubleZip) {
                runEncryption(
                    inputFile = tempRawZip,
                    outputDirectory = outputDirectory,
                    password = password,
                    originalFileName = tempRawZip.name,
                    onProgress = { snapshot ->
                        val overall = (50 + (snapshot.percent / 2)).coerceIn(0, 100)

                        onProgress?.invoke(
                            EncryptionManager.ProgressSnapshot(
                                processedBytes = overall.toLong(),
                                totalBytes = 100L
                            ),
                            "Encrypting final container... ${snapshot.percent}%"
                        )
                    }
                )
            } else {
                val secondLayerPassword = resolveSecondLayerPassword(
                    primaryPassword = password,
                    secondZipPassword = secondZipPassword
                )

                tempFirstLayerEnc = runEncryption(
                    inputFile = tempRawZip,
                    outputDirectory = context.cacheDir,
                    password = password,
                    originalFileName = tempRawZip.name,
                    onProgress = { snapshot ->
                        val overall = (50 + (snapshot.percent / 4)).coerceIn(0, 100)

                        onProgress?.invoke(
                            EncryptionManager.ProgressSnapshot(
                                processedBytes = overall.toLong(),
                                totalBytes = 100L
                            ),
                            "Encrypting container first layer... ${snapshot.percent}%"
                        )
                    }
                )

                applyDoubleEncryption(
                    encryptedFile = tempFirstLayerEnc!!,
                    secondLayerPassword = secondLayerPassword,
                    finalOutputDirectory = outputDirectory,
                    onProgress = { snapshot ->
                        val overall = (75 + (snapshot.percent / 4)).coerceIn(0, 100)

                        onProgress?.invoke(
                            EncryptionManager.ProgressSnapshot(
                                processedBytes = overall.toLong(),
                                totalBytes = 100L
                            ),
                            "Encrypting container second layer... ${snapshot.percent}%"
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
            for (tempFile in tempEncFiles) {
                secureDelete(tempFile)
            }

            secureDelete(tempRawZip)

            tempFirstLayerEnc?.let {
                if (it.exists()) secureDelete(it)
            }
        }
    }
}