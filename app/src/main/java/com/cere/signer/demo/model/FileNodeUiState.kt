package com.cere.signer.demo.model

sealed interface FileNodeUiState {
    data object Loading : FileNodeUiState

    data class Success(val data: FileNode.Directory, val lists: List<FileNode>) : FileNodeUiState

    data class Empty(val data: FileNode.Directory) : FileNodeUiState
}