package com.cere.signer

import android.content.Context
import com.meituan.android.walle.PayloadReader
import com.meituan.android.walle.PayloadWriter
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

class ApkSignatureUtil private constructor() {

    /**
     * 传入APK绝对路径，返回V2签名原始数据
     */
    private external fun getV2SignatureFromPath(apkPath: String): ByteArray?

    /**
     * 通过maps获取V2签名原始数据
     */
    private external fun getV2SignatureFromMaps(): ByteArray?

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
            val data = instance.getV2SignatureFromMaps()
            data?.let {
                return instance.getMd5(it)
            }
            return null
        }

        fun getV2SignatureIDValue(context: Context): ByteArray? {
            val path = context.externalCacheDir?.absolutePath + File.separator + "base.apk"
            val file = File(path)
            if (!file.exists()) {
                return null
            }
            return PayloadReader.get(file, 0x7109871a)
        }

        fun setV2SignatureIDValue(context: Context, byteArray: ByteArray): Boolean {
            val path = context.externalCacheDir?.absolutePath + File.separator + "base.apk"
            val file = File(path)
            if (!file.exists()) {
                return false
            }
            val byteBuffer = ByteBuffer.allocate(byteArray.size)
            byteBuffer.order(ByteOrder.LITTLE_ENDIAN)
            byteBuffer.put(byteArray, 0, byteArray.size)
            byteBuffer.flip()
            PayloadWriter.put(file, 0x7109871b, byteBuffer)
            return true
        }
    }
}