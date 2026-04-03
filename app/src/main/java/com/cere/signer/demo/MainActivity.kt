package com.cere.signer.demo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.cere.signer.ApkSignatureUtil
import com.cere.signer.demo.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btGetV2.setOnClickListener {
            ApkSignatureUtil.getV2Signature(this)?.let {
                binding.text.text = it.toHexString()
            }
        }
    }
}