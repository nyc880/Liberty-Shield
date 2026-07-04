package com.example.lock

import android.webkit.MimeTypeMap
import java.io.File
import java.util.Locale

enum class ResolvedFileType {
    IMAGE,
    VIDEO,
    AUDIO,
    PDF,
    TEXT,
    ARCHIVE,
    APK,
    ENCRYPTED,
    FOLDER,
    UNKNOWN
}

object FileTypeResolver {

    private val imageExt = setOf("jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "heif", "tif", "tiff")
    private val videoExt = setOf("mp4", "mkv", "mov", "avi", "webm", "3gp", "m4v", "ts", "mpg", "mpeg")
    private val audioExt = setOf("mp3", "wav", "aac", "m4a", "flac", "ogg", "opus", "amr")
    private val textExt = setOf("txt", "log", "json", "xml", "csv", "md", "kt", "java", "html", "js", "css", "yaml", "yml")
    private val archiveExt = setOf("zip", "rar", "7z", "tar", "gz")

    fun resolve(file: File): ResolvedFileType {
        if (file.isDirectory) return ResolvedFileType.FOLDER

        val ext = file.extension.lowercase(Locale.getDefault())
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)?.lowercase(Locale.getDefault())

        return when {
            ext in imageExt || mime?.startsWith("image/") == true -> ResolvedFileType.IMAGE
            ext in videoExt || mime?.startsWith("video/") == true -> ResolvedFileType.VIDEO
            ext in audioExt || mime?.startsWith("audio/") == true -> ResolvedFileType.AUDIO
            ext == "pdf" || mime == "application/pdf" -> ResolvedFileType.PDF
            ext in textExt || mime?.startsWith("text/") == true -> ResolvedFileType.TEXT
            ext in archiveExt -> ResolvedFileType.ARCHIVE
            ext == "apk" -> ResolvedFileType.APK
            ext == "enc" -> ResolvedFileType.ENCRYPTED
            else -> ResolvedFileType.UNKNOWN
        }
    }

    fun badge(type: ResolvedFileType, extension: String): String {
        return when (type) {
            ResolvedFileType.IMAGE -> "IMAGE"
            ResolvedFileType.VIDEO -> "VIDEO"
            ResolvedFileType.AUDIO -> "AUDIO"
            ResolvedFileType.PDF -> "PDF"
            ResolvedFileType.TEXT -> "TEXT"
            ResolvedFileType.ARCHIVE -> "ARCHIVE"
            ResolvedFileType.APK -> "APK"
            ResolvedFileType.ENCRYPTED -> "ENC"
            ResolvedFileType.FOLDER -> "FOLDER"
            ResolvedFileType.UNKNOWN -> if (extension.isBlank()) "FILE" else extension.uppercase(Locale.getDefault())
        }
    }

    fun icon(type: ResolvedFileType): Int {
        return when (type) {
            ResolvedFileType.IMAGE -> android.R.drawable.ic_menu_gallery
            ResolvedFileType.VIDEO -> android.R.drawable.ic_media_play
            ResolvedFileType.AUDIO -> android.R.drawable.ic_media_ff
            ResolvedFileType.PDF -> android.R.drawable.ic_menu_view
            ResolvedFileType.TEXT -> android.R.drawable.ic_menu_edit
            ResolvedFileType.ARCHIVE -> android.R.drawable.ic_menu_upload
            ResolvedFileType.APK -> android.R.drawable.sym_def_app_icon
            ResolvedFileType.ENCRYPTED -> android.R.drawable.ic_lock_lock
            ResolvedFileType.FOLDER -> android.R.drawable.ic_menu_agenda
            ResolvedFileType.UNKNOWN -> android.R.drawable.ic_menu_save
        }
    }

    fun tint(type: ResolvedFileType): String {
        return when (type) {
            ResolvedFileType.FOLDER -> "#86B7FF"
            ResolvedFileType.ENCRYPTED -> "#FFD76A"
            ResolvedFileType.IMAGE -> "#7CD8FF"
            ResolvedFileType.VIDEO -> "#B388FF"
            ResolvedFileType.AUDIO -> "#6EF0C2"
            ResolvedFileType.PDF -> "#FF8E8E"
            ResolvedFileType.TEXT -> "#9BE27A"
            ResolvedFileType.ARCHIVE -> "#FFB86B"
            ResolvedFileType.APK -> "#72F1B8"
            ResolvedFileType.UNKNOWN -> "#79C7FF"
        }
    }
}