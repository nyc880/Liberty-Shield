package com.example.lock.processor

import android.content.Context
import com.example.lock.crypto.EncryptionManager
import java.io.File

class JustFilesProcessor(context: Context) : BaseProcessor(context) {

    fun process(
        files: List<File>,
        password: CharArray,
        targetDir: File,
        deleteAfterEncryption: Boolean,
        onProgress: ((EncryptionManager.ProgressSnapshot, String) -> Unit)? = null
    ) {
        val validFiles = files.filter { it.exists() && it.isFile }
        val totalFiles = validFiles.size

        for ((index, file) in validFiles.withIndex()) {
            var outputFile: File? = null

            try {
                outputFile = runEncryption(
                    inputFile = file,
                    outputDirectory = targetDir,
                    password = password,
                    onProgress = { snapshot ->
                        val base = (index * 100) / totalFiles
                        val portion = snapshot.percent / totalFiles
                        val overall = (base + portion).coerceIn(0, 100)

                        onProgress?.invoke(
                            EncryptionManager.ProgressSnapshot(
                                processedBytes = overall.toLong(),
                                totalBytes = 100L
                            ),
                            "Encrypting ${file.name}... ${snapshot.percent}%"
                        )
                    }
                )

                onProgress?.invoke(
                    EncryptionManager.ProgressSnapshot(
                        processedBytes = (((index + 1) * 100) / totalFiles).coerceIn(0, 100).toLong(),
                        totalBytes = 100L
                    ),
                    "Completed ${file.name}"
                )

                if (deleteAfterEncryption) {
                    secureDelete(file)
                }

            } catch (e: Exception) {
                outputFile?.let {
                    if (it.exists()) secureDelete(it)
                }
                throw e
            }
        }
    }
}