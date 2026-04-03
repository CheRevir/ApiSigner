package com.cere.signer

import android.content.Context
import java.security.MessageDigest

class ApkSignatureUtil private constructor() {

    /**
     * 传入APK绝对路径，返回V2签名原始数据
     */
    private external fun getV2SignatureFromPath(apkPath: String): ByteArray?

    /**
     * 计算MD5，返回 32 位小写字符串
     */
    private fun getMd5(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    companion object {
        private val instance: ApkSignatureUtil by lazy { ApkSignatureUtil() }

        init {
            System.loadLibrary("signature")
        }

        /**
         * 获取V2签名数据
         */
        fun getV2Signature(context: Context): ByteArray? {
            val path = context.packageCodePath
            return instance.getV2SignatureFromPath(path)
        }

        /**
         * 获取V2签名MD5
         */
        fun getV2SignatureMD5(context: Context): String? {
            val path = context.packageCodePath
            val data = instance.getV2SignatureFromPath(path)
            data?.let {
                return@let instance.getMd5(it)
            }
            return null
        }
    }
}