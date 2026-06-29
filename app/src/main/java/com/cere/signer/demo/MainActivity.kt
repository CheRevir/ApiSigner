package com.cere.signer.demo

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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.tooling.preview.PreviewScreenSizes
import com.cere.signer.demo.ui.TopAppBar
import com.cere.signer.demo.ui.theme.AppTheme

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

@PreviewScreenSizes
@Composable
fun Home() {
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
                titleRes = R.string.app_name,
                navigationIcon = Icons.Rounded.Search,
                actionIcon = Icons.Rounded.Add,
            )
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