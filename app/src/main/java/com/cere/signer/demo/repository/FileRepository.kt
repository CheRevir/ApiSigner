package com.cere.signer.demo.repository

import com.cere.signer.ApkSignatureUtil
import com.cere.signer.demo.datastore.FileDataStore
import com.cere.signer.demo.model.ApkPayload
import com.cere.signer.demo.model.FileNode
import com.cere.signer.demo.model.Dispatcher
import com.cere.signer.demo.model.Dispatchers.IO
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import javax.inject.Inject

class FileRepository @Inject constructor(
    private val dataStore: FileDataStore,
    @param:Dispatcher(IO) private val ioDispatcher: CoroutineDispatcher,
) {

    fun getFile(path: String): Flow<FileNode> = dataStore.getFile(path)

    fun getFileChild(path: String): Flow<List<FileNode>> = dataStore.getFileChild(path)

    suspend fun getApkPayloads(path: String): List<ApkPayload> = withContext(ioDispatcher) {
        ApkSignatureUtil.getApkValue(path)
            ?.map { (id, buffer) ->
                val copy = buffer.duplicate()
                val bytes = ByteArray(copy.remaining())
                copy.get(bytes)
                ApkPayload(id, bytes)
            }
            .orEmpty()
    }

    suspend fun setApkPayload(path: String, id: Int, value: ByteArray): Boolean =
        withContext(ioDispatcher) {
            runCatching { ApkSignatureUtil.setApkValueById(path, id, value) }.getOrDefault(false)
        }
}
