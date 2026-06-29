package com.cere.signer.demo

import android.R.attr.navigationIcon
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.tooling.preview.Preview
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.cere.signer.demo.model.FileNode
import com.cere.signer.demo.model.FileNodeState
import com.cere.signer.demo.ui.TopAppBar
import com.cere.signer.demo.ui.theme.AppTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(statusBarStyle = SystemBarStyle.dark(Color.Transparent.toArgb()))
        setContent {
            AppTheme {
                Home()
            }
        }
    }

    /* override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
         binding = ActivityMainBinding.inflate(layoutInflater)
         setContentView(binding.root)

         binding.text.setText(this.packageCodePath)

         binding.btGetV2.setOnClickListener {
             ApkSignatureUtil.getV2SignatureIDValue(this)?.let {
                 binding.text.setText(it.toHexString())
             }
         }

         binding.btSetV2.setOnClickListener {
             val byteArray = hexToByteArray(binding.text.text.toString())
             if (ApkSignatureUtil.setV2SignatureIDValue(this, byteArray)) {
                 Toast.makeText(this, "写入成功", Toast.LENGTH_SHORT).show()
             }

         }
     }*/

    fun hexToByteArray(hex: String): ByteArray {
        val cleanHex = hex.replace(" ", "").replace("\n", "")
        return cleanHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}

@Composable
fun Home(viewModel: MainViewModel = hiltViewModel()) {
    val title by viewModel.currentPath.collectAsStateWithLifecycle()
    val node by viewModel.fileState.collectAsStateWithLifecycle()

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
            TopAppBar(
                title = title,
                subTile = if (node is FileNodeState.Success) (node as FileNodeState.Success).file.count.toString() else null,
                navigationIcon = Icons.Rounded.Search,
                actionIcon = Icons.Rounded.Add,
            )

            LazyColumn() { }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun TextPreview() {
    AppTheme {
        Home()
    }
}