package com.cere.signer.demo

import android.os.Environment
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cere.signer.demo.model.FileNode
import com.cere.signer.demo.model.FileNodeUiState
import com.cere.signer.demo.model.ApkDialogState
import com.cere.signer.demo.repository.FileRepository
import com.cere.signer.demo.repository.UserSettingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val fileRepository: FileRepository,
    private val userSettingRepository: UserSettingRepository
) : ViewModel() {
    private val _apkDialogState = MutableStateFlow<ApkDialogState>(ApkDialogState.Hidden)
    val apkDialogState: StateFlow<ApkDialogState> = _apkDialogState.asStateFlow()
    private val refreshRequests = MutableStateFlow(0)

    val mainPath: String by lazy { Environment.getExternalStorageDirectory().absolutePath }

    val currentPath: StateFlow<String> = userSettingRepository.currentPath.stateIn(
        viewModelScope,
        SharingStarted.Lazily,
        mainPath
    )

    @OptIn(ExperimentalCoroutinesApi::class)
    val fileUiState: StateFlow<FileNodeUiState> =
        currentPath.combine(refreshRequests) { path, _ -> path }.flatMapLatest { path ->
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

    fun refreshFiles() {
        refreshRequests.value += 1
    }

    fun openApk(path: String) {
        _apkDialogState.value = ApkDialogState.Loading(path)
        viewModelScope.launch {
            _apkDialogState.value = runCatching {
                ApkDialogState.Content(path, fileRepository.getApkPayloads(path))
            }.getOrElse {
                ApkDialogState.Error(path, it.message ?: "无法读取 APK 签名数据")
            }
        }
    }

    fun dismissApkDialog() {
        if ((_apkDialogState.value as? ApkDialogState.Content)?.isSaving != true) {
            _apkDialogState.value = ApkDialogState.Hidden
        }
    }

    fun writeApkPayload(id: Int, value: ByteArray) {
        val state = _apkDialogState.value as? ApkDialogState.Content ?: return
        _apkDialogState.value = state.copy(isSaving = true, message = null)
        viewModelScope.launch {
            val success = fileRepository.setApkPayload(state.path, id, value)
            _apkDialogState.value = if (success) {
                ApkDialogState.Content(
                    path = state.path,
                    payloads = fileRepository.getApkPayloads(state.path),
                    message = "写入成功",
                )
            } else {
                state.copy(isSaving = false, message = "写入失败，请检查文件权限")
            }
        }
    }
}
