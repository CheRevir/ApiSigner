package com.cere.signer.demo.ui.page

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.cere.signer.demo.MainViewModel
import com.cere.signer.demo.model.FileNodeUiState
import com.cere.signer.demo.ui.FileItem
import com.cere.signer.demo.ui.FilePermissionEffect
import com.cere.signer.demo.ui.TopAppBar
import com.cere.signer.demo.ui.theme.AppTheme

@Composable
fun HomeScreen(viewModel: MainViewModel = hiltViewModel()) {
    val title by viewModel.currentPath.collectAsStateWithLifecycle()
    val fileUiState by viewModel.fileUiState.collectAsStateWithLifecycle()
    HomeScreen(title = title, fileUiState = fileUiState, onClick = viewModel::setCurrentPath)
}

@Preview(showBackground = true, showSystemUi = true)
@Composable
private fun HomeScreenPreview() {
    AppTheme {
        HomeScreen(
            title = stringResource(android.R.string.untitled),
            fileUiState = FileNodeUiState.Loading
        )
    }
}

@Composable
internal fun HomeScreen(
    title: String,
    fileUiState: FileNodeUiState,
    onClick: (path: String) -> Unit = {}
) {
    Scaffold(
        containerColor = Color.Transparent,
        contentColor = MaterialTheme.colorScheme.onBackground,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        modifier = Modifier.fillMaxSize(),
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            val subTitle: String? by remember(fileUiState) {
                when (fileUiState) {
                    is FileNodeUiState.Success -> {
                        mutableStateOf(fileUiState.data.count.toString())
                    }

                    else -> {
                        mutableStateOf(null)
                    }
                }
            }

            TopAppBar(
                title = title,
                subTile = subTitle,
                navigationIcon = Icons.Rounded.Search,
                actionIcon = Icons.Rounded.Add,
            )

            LazyColumn(modifier = Modifier.fillMaxSize()) {
                when (fileUiState) {
                    is FileNodeUiState.Empty -> {
                        item {
                            FileItem(title = "..") {
                                onClick(fileUiState.data.parent)
                            }
                        }
                    }

                    is FileNodeUiState.Success -> {
                        item {
                            FileItem(title = "..") {
                                onClick(fileUiState.data.parent)
                            }
                        }

                        items(
                            fileUiState.data.count,
                            key = {
                                fileUiState.lists[it].path
                            },
                            contentType = {
                                fileUiState.lists[it].type
                            }) {
                            val item = fileUiState.lists[it]
                            FileItem(item) {
                                if (item.isDirectory) {
                                    onClick(fileUiState.lists[it].path)
                                } else {

                                }
                            }
                        }
                    }

                    else -> {

                    }
                }
            }

        }
    }

    FilePermissionEffect()
}