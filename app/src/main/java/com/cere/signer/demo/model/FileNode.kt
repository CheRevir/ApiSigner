package com.cere.signer.demo.model

sealed class FileNode private constructor(
    open val parent: String,
    open val child: String,
    open val type: FileType,
) : Comparator<FileNode> {
    val path: String
        get() {
            if (child.isEmpty()) {
                return parent
            }
            return parent + java.io.File.separator + child
        }

    val name: String
        get() {
            if (child.isEmpty()) {
                return parent
            }
            return child
        }

    override fun compare(o1: FileNode, o2: FileNode): Int {
        if (o1.isDirectory && !o2.isDirectory) {
            return 1
        }
        if (!o1.isDirectory && o2.isDirectory) {
            return -1
        }
        return o1.name.compareTo(o2.name)
    }

    data class File(
        override val parent: String,
        override val child: String,
        override val type: FileType
    ) : FileNode(parent, child, type)

    data class Directory(
        override val parent: String,
        override val child: String,
        val count: Int
    ) : FileNode(parent, child, FileType.FOLDER)

    val isDirectory: Boolean
        get() = type == FileType.FOLDER

    companion object {
        fun fromFile(file: java.io.File): FileNode {
            val path = file.absolutePath
            val index = path.lastIndexOf(java.io.File.separator)
            val parent = if (index > 0) path.substring(0, index) else java.io.File.separator
            val child = if (index + 1 < path.length) path.substring(index + 1, path.length) else ""
            if (file.isDirectory) {
                return Directory(
                    parent,
                    child,
                    file.list()?.count() ?: 0
                )
            }
            return File(parent, child, FileType.UNKNOW)
        }
    }
}