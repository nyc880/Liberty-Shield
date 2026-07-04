package com.example.lock

import android.app.Activity
import android.content.Context

object SafeExit {

    fun performSafeExit(activity: Activity) {
        try {
            zeroSensitiveData()
            clearTemporaryCaches(activity)

            activity.finishAffinity()

            if (android.os.Build.VERSION.SDK_INT >= 21) {
                activity.finishAndRemoveTask()
            }

            android.os.Process.killProcess(android.os.Process.myPid())
            System.exit(0)

        } catch (_: Exception) {
            try {
                activity.finishAffinity()
                if (android.os.Build.VERSION.SDK_INT >= 21) {
                    activity.finishAndRemoveTask()
                }
            } catch (_: Exception) {}

            android.os.Process.killProcess(android.os.Process.myPid())
            System.exit(0)
        }
    }

    private fun zeroSensitiveData() {
        try {
            val passphrase = CharArray(256)
            passphrase.fill('\u0000')

            val key = ByteArray(64)
            key.fill(0)

            try {
                val secureErase = Class.forName("com.example.lock.crypto.SecureErase")
                secureErase.getDeclaredMethod("wipe", ByteArray::class.java)
                    .apply { isAccessible = true }
                    .invoke(null, key)

                secureErase.getDeclaredMethod("wipeChars", CharArray::class.java)
                    .apply { isAccessible = true }
                    .invoke(null, passphrase)
            } catch (_: Exception) {
            }

            System.gc()
        } catch (_: Exception) {
        }
    }

    private fun clearTemporaryCaches(context: Context) {
        try {
            context.cacheDir?.deleteRecursively()
            context.externalCacheDir?.deleteRecursively()

            context.filesDir?.listFiles()?.forEach { file ->
                try {
                    val name = file.name.lowercase()
                    if (name.contains("temp") || name.contains("cache") ||
                        name.startsWith(".") || name.contains("secure")) {
                        file.deleteRecursively()
                    }
                } catch (_: Exception) {
                }
            }

            System.gc()
        } catch (_: Exception) {
        }
    }
}