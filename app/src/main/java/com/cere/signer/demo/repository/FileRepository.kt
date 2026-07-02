package com.cere.signer.demo.repository

import com.cere.signer.demo.datastore.FileDataStore
import com.cere.signer.demo.model.FileNode
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class FileRepository @Inject constructor(
    private val dataStore: FileDataStore
) {

    fun getFile(path: String): Flow<FileNode> = dataStore.getFile(path)

    fun getFileChild(path: String): Flow<List<FileNode>> = dataStore.getFileChild(path)
}