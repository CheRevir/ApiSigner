package com.cere.signer.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import com.cere.signer.demo.ui.page.HomeScreen
import com.cere.signer.demo.ui.theme.AppTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(statusBarStyle = SystemBarStyle.dark(Color.Transparent.toArgb()))
        setContent {
            AppTheme {
                HomeScreen()
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