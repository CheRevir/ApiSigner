package com.cere.signer.demo

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.cere.signer.ApkSignatureUtil
import com.cere.signer.demo.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
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
    }

    fun hexToByteArray(hex: String): ByteArray {
        val cleanHex = hex.replace(" ", "").replace("\n", "")
        return cleanHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}