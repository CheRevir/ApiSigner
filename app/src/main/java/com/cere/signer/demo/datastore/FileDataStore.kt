package com.cere.signer.demo.datastore

import com.cere.signer.demo.model.Dispatcher
import com.cere.signer.demo.model.Dispatchers.IO
import com.cere.signer.demo.model.FileNode
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import javax.inject.Inject

class FileDataStore @Inject constructor(
    @Dispatcher(IO) private val ioDispatcher: CoroutineDispatcher
) {

    fun getFile(path: String): Flow<FileNode> = flow {
        emit(FileNode(path))
    }.flowOn(ioDispatcher)
}