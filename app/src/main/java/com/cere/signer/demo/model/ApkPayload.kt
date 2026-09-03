package com.cere.signer.demo.model

data class ApkPayload(
    val id: Int,
    val value: ByteArray,
) {
    val idHex: String
        get() = "0x%08X".format(id)

    val displayName: String
        get() = when (id) {
            0x7109871A -> "APK 签名方案 v2"
            0xF05368C0.toInt() -> "APK 签名方案 v3"
            0x1B93AD61 -> "APK 签名方案 v3.1"
            0x42726577 -> "Verity 对齐填充"
            0x6DFF800D -> "来源戳签名"
            0x71777777 -> "Walle 渠道信息"
            else -> "自定义数据"
        }

    val valueHex: String
        get() = value.joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }

    val textValue: String?
        get() {
            val text = value.toString(Charsets.UTF_8)
            return text.takeIf {
                it.isNotEmpty() &&
                    it.toByteArray(Charsets.UTF_8).contentEquals(value) &&
                    it.all { char -> char == '\n' || char == '\r' || char == '\t' || !char.isISOControl() }
            }
        }

    override fun equals(other: Any?): Boolean =
        other is ApkPayload && id == other.id && value.contentEquals(other.value)

    override fun hashCode(): Int = 31 * id + value.contentHashCode()
}

sealed interface ApkDialogState {
    data object Hidden : ApkDialogState
    data class Loading(val path: String) : ApkDialogState
    data class Content(
        val path: String,
        val payloads: List<ApkPayload>,
        val isSaving: Boolean = false,
        val message: String? = null,
    ) : ApkDialogState
    data class Error(val path: String, val message: String) : ApkDialogState
}
