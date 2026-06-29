package com.cere.signer.demo.model

import java.io.File

data class FileNode(val path: String) {
    private val file: File by lazy { File(path) }

    fun hasParent(): Boolean {
        return file.parent != null
    }

    fun getFile(): File {
        return this.file
    }

    fun getParent(): FileNode? = file.parent?.let { FileNode(it) }
        
    fun getList(): List<FileNode>? {
        return file.list()?.map { FileNode(it) }
    }
}