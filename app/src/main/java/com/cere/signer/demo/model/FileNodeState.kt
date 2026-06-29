package com.cere.signer.demo.model

sealed interface FileNodeState {
    data object Loading : FileNodeState

    data class Success(val file: FileNode?) : FileNodeState
}