package com.cere.signer.demo.datastore

import com.cere.signer.demo.model.Dispatcher
import com.cere.signer.demo.model.Dispatchers.IO
import com.cere.signer.demo.model.FileNode
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import java.io.File
import javax.inject.Inject

class FileDataStore @Inject constructor(
    @Dispatcher(IO) private val ioDispatcher: CoroutineDispatcher
) {

    fun getFile(path: String): Flow<FileNode> = flow {
        val file = File(path)
        emit(FileNode.fromFile(file))
    }.flowOn(ioDispatcher)

    fun getFileChild(path: String): Flow<List<FileNode>> = flow {
        val file = File(path)
        if (file.isFile) {
            emit(listOf())
        } else {
            emit(file.listFiles()?.map { FileNode.fromFile(it) } ?: listOf())
        }
    }.flowOn(ioDispatcher)
}