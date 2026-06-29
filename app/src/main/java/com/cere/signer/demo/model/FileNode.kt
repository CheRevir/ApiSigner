package com.cere.signer.demo.model

import java.io.File

data class FileNode(val path: String) {
    val file: File by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { File(path) }

    val hasParent = file.parent != null

    val parent: FileNode? = file.parent?.let { FileNode(it) }

    val lists: List<FileNode>? = file.list()?.map { FileNode(it) }

    val count = lists?.count() ?: 0
}