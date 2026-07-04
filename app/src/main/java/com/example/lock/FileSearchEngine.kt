package com.example.lock

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.coroutineContext

object FileSearchEngine {

    private val indexedEntries = ArrayList<SearchEntry>()
    private val indexedPaths = HashSet<String>()
    private val searchCache = ConcurrentHashMap<String, List<File>>()
    private val indexMutex = Mutex()

    @Volatile
    private var indexedRootPath: String? = null

    suspend fun ensureIndexed(root: File) = withContext(Dispatchers.IO) {
        val rootPath = root.absolutePath
        if (indexedRootPath == rootPath && indexedEntries.isNotEmpty()) return@withContext

        indexMutex.withLock {
            if (indexedRootPath == rootPath && indexedEntries.isNotEmpty()) return@withLock

            indexedEntries.clear()
            indexedPaths.clear()
            searchCache.clear()
            indexWalk(root)
            indexedRootPath = rootPath
        }
    }

    suspend fun searchFast(root: File, query: String): List<File> = withContext(Dispatchers.Default) {
        val normalized = normalize(query)
        if (normalized.isBlank()) return@withContext emptyList()

        ensureIndexed(root)

        val cacheKey = root.absolutePath + "::" + normalized
        searchCache[cacheKey]?.let { return@withContext it }

        val tokens = normalized.split(" ").filter { it.isNotBlank() }

        val results = indexedEntries.asSequence()
            .mapNotNull { entry ->
                val rank = rank(entry, tokens)
                if (rank == Int.MAX_VALUE) null else RankedFile(entry.file, rank)
            }
            .sortedWith(
                compareBy<RankedFile> { !it.file.isDirectory }
                    .thenBy { it.rank }
                    .thenBy { it.file.name.length }
                    .thenBy { it.file.name.lowercase() }
            )
            .map { it.file }
            .toList()

        searchCache[cacheKey] = results
        return@withContext results
    }

    private fun rank(entry: SearchEntry, tokens: List<String>): Int {
        var score = 0
        for (token in tokens) {
            val tokenScore = when {
                entry.normalizedName == token -> 0
                entry.normalizedName.startsWith(token) -> 1
                entry.normalizedName.contains(token) -> 2
                entry.normalizedPath.contains("/$token") -> 3
                entry.normalizedPath.contains(token) -> 4
                else -> Int.MAX_VALUE
            }

            if (tokenScore == Int.MAX_VALUE) return Int.MAX_VALUE
            score += tokenScore
        }
        return score
    }

    private fun normalize(value: String): String {
        return value
            .trim()
            .lowercase()
            .replace('\\', '/')
            .replace('_', ' ')
            .replace('-', ' ')
            .replace(Regex("\\s+"), " ")
    }

    private suspend fun indexWalk(current: File) {
        coroutineContext.ensureActive()

        if (!current.exists()) return
        if (current.name.startsWith(".")) return

        if (indexedPaths.add(current.absolutePath)) {
            indexedEntries.add(
                SearchEntry(
                    file = current,
                    normalizedName = normalize(current.name),
                    normalizedPath = normalize(current.absolutePath)
                )
            )
        }

        if (!current.isDirectory) return

        val children = try {
            current.listFiles()
        } catch (_: Exception) {
            null
        } ?: return

        for (child in children) {
            coroutineContext.ensureActive()
            indexWalk(child)
        }
    }

    fun invalidateIndex() {
        indexedRootPath = null
        indexedEntries.clear()
        indexedPaths.clear()
        searchCache.clear()
    }

    private data class SearchEntry(
        val file: File,
        val normalizedName: String,
        val normalizedPath: String
    )

    private data class RankedFile(
        val file: File,
        val rank: Int
    )
}