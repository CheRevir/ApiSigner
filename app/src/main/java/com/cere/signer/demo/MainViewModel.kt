package com.cere.signer.demo

import android.os.Environment
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.cere.signer.demo.model.FileNodeState
import com.cere.signer.demo.repository.FileRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(repository: FileRepository) : ViewModel() {

    val fileState: StateFlow<FileNodeState> =
        repository.getFile(Environment.getExternalStorageDirectory().parent)
            .map(FileNodeState::Success)
            .stateIn(
                viewModelScope, started = SharingStarted.WhileSubscribed(5_000),
                FileNodeState.Loading
            )
}