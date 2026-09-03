package com.cere.signer.demo.ui.page

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.cere.signer.demo.MainViewModel
import com.cere.signer.demo.model.ApkDialogState
import com.cere.signer.demo.model.FileNode
import com.cere.signer.demo.model.FileNodeUiState
import com.cere.signer.demo.model.FileType
import com.cere.signer.demo.ui.ApkSignatureDialog
import com.cere.signer.demo.ui.FileItem
import com.cere.signer.demo.ui.FilePermissionEffect
import com.cere.signer.demo.ui.TopAppBar
import com.cere.signer.demo.ui.theme.AppTheme

@Composable
fun HomeScreen(viewModel: MainViewModel = hiltViewModel()) {
    val title by viewModel.currentPath.collectAsStateWithLifecycle()
    val fileUiState by viewModel.fileUiState.collectAsStateWithLifecycle()
    val apkDialogState by viewModel.apkDialogState.collectAsStateWithLifecycle()

    HomeScreen(
        title = title,
        mainPath = viewModel.mainPath,
        fileUiState = fileUiState,
        apkDialogState = apkDialogState,
        onOpenPath = viewModel::setCurrentPath,
        onOpenApk = viewModel::openApk,
        onDismissDialog = viewModel::dismissApkDialog,
        onWritePayload = viewModel::writeApkPayload,
        onPermissionChanged = viewModel::refreshFiles,
    )
}

@Composable
internal fun HomeScreen(
    title: String,
    mainPath: String,
    fileUiState: FileNodeUiState,
    apkDialogState: ApkDialogState = ApkDialogState.Hidden,
    onOpenPath: (String) -> Unit = {},
    onOpenApk: (String) -> Unit = {},
    onDismissDialog: () -> Unit = {},
    onWritePayload: (Int, ByteArray) -> Unit = { _, _ -> },
    onPermissionChanged: () -> Unit = {},
) {
    val directory = when (fileUiState) {
        is FileNodeUiState.Success -> fileUiState.data
        is FileNodeUiState.Empty -> fileUiState.data
        else -> null
    }
    val canNavigateUp = title != mainPath && directory != null

    BackHandler(enabled = canNavigateUp) { onOpenPath(directory!!.parent) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        contentColor = MaterialTheme.colorScheme.onBackground,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = directory?.name?.ifBlank { "文件" } ?: "文件",
                subTile = title,
                navigationIcon = if (canNavigateUp) Icons.AutoMirrored.Rounded.ArrowBack else null,
                onNavigationClick = { directory?.let { onOpenPath(it.parent) } },
            )
        },
    ) { innerPadding ->
        Box(Modifier.fillMaxSize().padding(innerPadding)) {
            when (fileUiState) {
                FileNodeUiState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                is FileNodeUiState.Empty -> Text(
                    text = "此文件夹为空",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.align(Alignment.Center),
                )
                is FileNodeUiState.Success -> LazyColumn(Modifier.fillMaxSize()) {
                    items(
                        items = fileUiState.lists,
                        key = FileNode::path,
                        contentType = FileNode::type,
                    ) { item ->
                        FileItem(item) {
                            when (item.type) {
                                FileType.FOLDER -> onOpenPath(item.path)
                                FileType.APK -> onOpenApk(item.path)
                                FileType.UNKNOW -> Unit
                            }
                        }
                    }
                }
            }
        }
    }

    if (apkDialogState !is ApkDialogState.Hidden) {
        ApkSignatureDialog(apkDialogState, onDismissDialog, onWritePayload)
    }
    FilePermissionEffect(onPermissionChanged)
}

@Preview(showBackground = true, showSystemUi = true)
@Composable
private fun HomeScreenPreview() {
    AppTheme {
        HomeScreen(
            title = "/storage/emulated/0/Download",
            mainPath = "/storage/emulated/0",
            fileUiState = FileNodeUiState.Loading,
        )
    }
}
