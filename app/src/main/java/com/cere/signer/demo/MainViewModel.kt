package com.cere.signer.demo

import android.os.Environment
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cere.signer.demo.model.FileNode
import com.cere.signer.demo.model.FileNodeUiState
import com.cere.signer.demo.repository.FileRepository
import com.cere.signer.demo.repository.UserSettingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    fileRepository: FileRepository,
    private val userSettingRepository: UserSettingRepository
) : ViewModel() {
    val mainPath: String by lazy { Environment.getExternalStorageDirectory().absolutePath }

    val currentPath: StateFlow<String> = userSettingRepository.currentPath.stateIn(
        viewModelScope,
        SharingStarted.Lazily,
        mainPath
    )

    @OptIn(ExperimentalCoroutinesApi::class)
    val fileUiState: StateFlow<FileNodeUiState> =
        currentPath.flatMapLatest { path ->
            fileRepository.getFile(path)
                .filter { it.isDirectory }
                .map { it as FileNode.Directory }
                .combine(fileRepository.getFileChild(path)) { data, child ->
                    if (child.count() > 0) {
                        FileNodeUiState.Success(data, child)
                    } else {
                        FileNodeUiState.Empty(data)
                    }
                }
        }
            .stateIn(
                viewModelScope,
                SharingStarted.WhileSubscribed(5_000),
                FileNodeUiState.Loading
            )

    fun setCurrentPath(path: String) {
        if (!path.startsWith(mainPath)) {
            return
        }
        viewModelScope.launch {
            userSettingRepository.setCurrentPath(path)
        }
    }
}