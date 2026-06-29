package com.cere.signer.demo

import android.os.Environment
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cere.signer.demo.model.FileNodeState
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
    val currentPath: StateFlow<String> = userSettingRepository.currentPath.stateIn(
        viewModelScope,
        SharingStarted.Lazily,
        Environment.getExternalStorageDirectory().absolutePath
    )

    @OptIn(ExperimentalCoroutinesApi::class)
    val fileState: StateFlow<FileNodeState> =
        currentPath.flatMapLatest {
            fileRepository.getFile(it)
                .map(FileNodeState::Success)
        }
            .stateIn(
                viewModelScope, started = SharingStarted.WhileSubscribed(5_000),
                FileNodeState.Loading
            )

    fun setCurrentPath(path: String) {
        viewModelScope.launch {
            userSettingRepository.setCurrentPath(path)
        }
    }
}