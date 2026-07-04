package com.example.lock

import android.content.Context
import android.os.Build
import android.os.Environment
import android.util.Log
import com.example.lock.crypto.EncryptionManager
import com.example.lock.processor.FilesAndZipProcessor
import com.example.lock.processor.JustFilesProcessor
import com.example.lock.processor.JustZipProcessor
import java.io.File
import java.io.IOException

class EncryptionProcessor(private val context: Context) {

    companion object {
        const val MODE_JUST_FILES = 1
        const val MODE_JUST_ZIP = 2
        const val MODE_FILES_AND_ZIP = 3

        const val TARGET_FOLDER_NAME = "ENC"
        const val LOG_TAG = "LOCK_AUDIT"
    }

    fun execute(
        files: List<File>,
        password: CharArray,
        mode: Int,
        deleteAfterEncryption: Boolean,
        doubleZip: Boolean = false,
        secondZipPassword: CharArray? = null,
        onProgress: ((EncryptionManager.ProgressSnapshot, String) -> Unit)? = null
    ) {
        if (files.isEmpty()) {
            Log.e(LOG_TAG, "Execution halted: Input file list is empty.")
            throw IllegalArgumentException("No files provided for encryption")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Log.e(LOG_TAG, "Execution halted: MANAGE_EXTERNAL_STORAGE permission is not granted by user.")
                throw SecurityException("All Files Access permission is required. Please enable it in system settings.")
            }
        }

        val targetDir = File(Environment.getExternalStorageDirectory(), TARGET_FOLDER_NAME)
        if (!targetDir.exists()) {
            val isCreated = targetDir.mkdirs()
            if (!isCreated) {
                Log.e(LOG_TAG, "Critical: Failed to create target directory at: ${targetDir.absolutePath}")
                throw IOException("Could not create storage directory: $TARGET_FOLDER_NAME")
            }
        }

        Log.d(LOG_TAG, "Pipeline initialized. Target Directory: ${targetDir.absolutePath}")
        Log.d(LOG_TAG, "Total files payload to process: ${files.size}")

        try {
            when (mode) {
                MODE_JUST_FILES -> {
                    val processor = JustFilesProcessor(context)
                    processor.process(files, password, targetDir, deleteAfterEncryption, onProgress)
                }

                MODE_JUST_ZIP -> {
                    val processor = JustZipProcessor(context)
                    processor.process(
                        files = files,
                        password = password,
                        outputDirectory = targetDir,
                        deleteAfterEncryption = deleteAfterEncryption,
                        doubleZip = doubleZip,
                        secondZipPassword = secondZipPassword,
                        onProgress = onProgress
                    )
                }

                MODE_FILES_AND_ZIP -> {
                    val processor = FilesAndZipProcessor(context)
                    processor.process(
                        files = files,
                        password = password,
                        outputDirectory = targetDir,
                        deleteAfterEncryption = deleteAfterEncryption,
                        doubleZip = doubleZip,
                        secondZipPassword = secondZipPassword,
                        onProgress = onProgress
                    )
                }

                else -> throw IllegalArgumentException("Unknown encryption mode specified")
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Processor pipeline internal crash trapped inside EncryptionProcessor!", e)
            throw e
        }
    }
}