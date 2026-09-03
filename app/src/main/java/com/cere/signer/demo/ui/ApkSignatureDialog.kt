package com.cere.signer.demo.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Android
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.cere.signer.demo.model.ApkDialogState
import com.cere.signer.demo.model.ApkPayload
import java.io.File

private enum class ValueFormat { TEXT, HEX }

@Composable
fun ApkSignatureDialog(
    state: ApkDialogState,
    onDismiss: () -> Unit,
    onWrite: (Int, ByteArray) -> Unit,
) {
    var editing by rememberSaveable(state.path) { mutableStateOf(false) }
    var idInput by rememberSaveable(state.path) { mutableStateOf("") }
    var valueInput by rememberSaveable(state.path) { mutableStateOf("") }
    var format by rememberSaveable(state.path) { mutableStateOf(ValueFormat.TEXT) }
    val parsedId = parseId(idInput)
    val parsedValue = parseValue(valueInput, format)
    val saving = (state as? ApkDialogState.Content)?.isSaving == true

    Dialog(
        onDismissRequest = { if (!saving) onDismiss() },
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .heightIn(min = 280.dp, max = 680.dp),
            shape = RoundedCornerShape(8.dp),
            color = Color.White,
            contentColor = Color(0xFF1B1B1F),
            tonalElevation = 6.dp,
        ) {
            Column {
                DialogHeader(state.path)
                HorizontalDivider()

                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .padding(horizontal = 20.dp, vertical = 16.dp),
                ) {
                    when (state) {
                        is ApkDialogState.Loading -> CircularProgressIndicator(Modifier.align(Alignment.Center))
                        is ApkDialogState.Error -> Text(
                            text = state.message,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.align(Alignment.Center),
                        )
                        is ApkDialogState.Content -> if (editing) {
                            PayloadEditor(
                                idInput = idInput,
                                valueInput = valueInput,
                                format = format,
                                enabled = !saving,
                                idValid = parsedId != null,
                                valueValid = parsedValue != null,
                                onIdChange = { idInput = it },
                                onValueChange = { valueInput = it },
                                onFormatChange = { format = it },
                            )
                        } else {
                            PayloadList(state.payloads, state.message)
                        }
                        ApkDialogState.Hidden -> Unit
                    }
                }

                HorizontalDivider()
                Row(
                    modifier = Modifier.fillMaxWidth().padding(12.dp),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (state is ApkDialogState.Content && editing && !saving) {
                        TextButton(
                            onClick = { editing = false },
                            colors = ButtonDefaults.textButtonColors(
                                contentColor = Color(0xFF1769AA),
                            ),
                        ) { Text("返回") }
                        Spacer(Modifier.width(8.dp))
                        Button(
                            enabled = parsedId != null && parsedValue != null,
                            onClick = { onWrite(parsedId!!, parsedValue!!) },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF1769AA),
                                contentColor = Color.White,
                                disabledContainerColor = Color(0xFFD5D5DA),
                                disabledContentColor = Color(0xFF77777F),
                            ),
                        ) { Text("保存") }
                    } else {
                        TextButton(
                            onClick = onDismiss,
                            enabled = !saving,
                            colors = ButtonDefaults.textButtonColors(
                                contentColor = Color(0xFF1769AA),
                            ),
                        ) { Text("关闭") }
                        if (state is ApkDialogState.Content) {
                            Spacer(Modifier.width(8.dp))
                            Button(
                                onClick = { editing = true },
                                enabled = !saving,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = Color(0xFF1769AA),
                                    contentColor = Color.White,
                                    disabledContainerColor = Color(0xFFD5D5DA),
                                    disabledContentColor = Color(0xFF77777F),
                                ),
                            ) {
                                if (saving) {
                                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                                    Spacer(Modifier.width(8.dp))
                                    Text("写入中")
                                } else {
                                    Text("修改")
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DialogHeader(path: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(20.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Rounded.Android,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(32.dp),
        )
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text("APK 签名数据", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Text(
                text = File(path).name,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

private val ApkDialogState.path: String
    get() = when (this) {
        is ApkDialogState.Loading -> path
        is ApkDialogState.Content -> path
        is ApkDialogState.Error -> path
        ApkDialogState.Hidden -> ""
    }

@Composable
private fun PayloadList(payloads: List<ApkPayload>, message: String?) {
    Column(Modifier.fillMaxSize()) {
        message?.let {
                    Text(it, color = Color(0xFF1769AA), modifier = Modifier.padding(bottom = 8.dp))
        }
        if (payloads.isEmpty()) {
            Text(
                "未找到 APK Signing Block 数据",
                color = Color(0xFF4A4A52),
                modifier = Modifier.align(Alignment.CenterHorizontally).padding(top = 48.dp),
            )
        } else {
            Text(
                "Signing Block · ${payloads.size} 项",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 10.dp),
            )
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(payloads, key = ApkPayload::id) { PayloadRow(it) }
            }
        }
    }
}

@Composable
private fun PayloadRow(payload: ApkPayload) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surfaceContainer, RoundedCornerShape(6.dp))
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = payload.displayName,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f),
            )
            Text(
                text = payload.idHex,
                style = MaterialTheme.typography.labelMedium.copy(fontFamily = FontFamily.Monospace),
                color = Color(0xFF1769AA),
            )
        }
        SelectionContainer {
            Text(
                text = payload.textValue ?: payload.valueHex,
                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color = Color(0xFF4A4A52),
                maxLines = 4,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Text(
            text = "${payload.value.size} 字节 · ${if (payload.textValue != null) "UTF-8 文本" else "十六进制"}",
            style = MaterialTheme.typography.labelSmall,
            color = Color(0xFF4A4A52),
        )
    }
}

@Composable
private fun PayloadEditor(
    idInput: String,
    valueInput: String,
    format: ValueFormat,
    enabled: Boolean,
    idValid: Boolean,
    valueValid: Boolean,
    onIdChange: (String) -> Unit,
    onValueChange: (String) -> Unit,
    onFormatChange: (ValueFormat) -> Unit,
) {
    val fieldColors = OutlinedTextFieldDefaults.colors(
        focusedTextColor = Color(0xFF1B1B1F),
        unfocusedTextColor = Color(0xFF1B1B1F),
        disabledTextColor = Color(0xFF77777F),
        focusedPlaceholderColor = Color(0xFF77777F),
        unfocusedPlaceholderColor = Color(0xFF77777F),
        disabledPlaceholderColor = Color(0xFFAAAAAF),
        focusedLabelColor = Color(0xFF1769AA),
        unfocusedLabelColor = Color(0xFF4A4A52),
        disabledLabelColor = Color(0xFF77777F),
        focusedSupportingTextColor = Color(0xFF4A4A52),
        unfocusedSupportingTextColor = Color(0xFF4A4A52),
        errorSupportingTextColor = Color(0xFFB3261E),
        focusedBorderColor = Color(0xFF1769AA),
        unfocusedBorderColor = Color(0xFF77777F),
        disabledBorderColor = Color(0xFFAAAAAF),
        errorBorderColor = Color(0xFFB3261E),
        errorTextColor = Color(0xFF1B1B1F),
        errorLabelColor = Color(0xFFB3261E),
        cursorColor = Color(0xFF1769AA),
        focusedContainerColor = Color.White,
        unfocusedContainerColor = Color.White,
        disabledContainerColor = Color(0xFFF2F2F4),
        errorContainerColor = Color.White,
    )
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("写入自定义数据", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = Color(0xFF1B1B1F))
        Text("使用已有 ID 会覆盖对应数据。", color = Color(0xFF4A4A52))
        OutlinedTextField(
            value = idInput,
            onValueChange = onIdChange,
            enabled = enabled,
            label = { Text("ID（十六进制）") },
            placeholder = { Text("0x71777777") },
            supportingText = { if (idInput.isNotBlank() && !idValid) Text("请输入最多 8 位十六进制数") },
            isError = idInput.isNotBlank() && !idValid,
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            colors = fieldColors,
        )
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            ValueFormat.entries.forEachIndexed { index, item ->
                SegmentedButton(
                    selected = format == item,
                    onClick = { onFormatChange(item) },
                    shape = SegmentedButtonDefaults.itemShape(index, ValueFormat.entries.size),
                    label = {
                        Text(
                            if (item == ValueFormat.TEXT) "UTF-8 文本" else "十六进制",
                            color = if (format == item) Color.White else Color(0xFF1B1B1F),
                        )
                    },
                    colors = SegmentedButtonDefaults.colors(
                        activeContainerColor = Color(0xFF1769AA),
                        activeContentColor = Color.White,
                        inactiveContainerColor = Color.White,
                        inactiveContentColor = Color(0xFF1B1B1F),
                        activeBorderColor = Color(0xFF1769AA),
                        inactiveBorderColor = Color(0xFF77777F),
                    ),
                )
            }
        }
        OutlinedTextField(
            value = valueInput,
            onValueChange = onValueChange,
            enabled = enabled,
            label = { Text("Value") },
            placeholder = { Text(if (format == ValueFormat.TEXT) "输入文本内容" else "例如 DE AD BE EF") },
            supportingText = { if (valueInput.isNotBlank() && !valueValid) Text("十六进制必须由完整字节组成") },
            isError = valueInput.isNotBlank() && !valueValid,
            minLines = 4,
            maxLines = 8,
            modifier = Modifier.fillMaxWidth(),
            colors = fieldColors,
        )
    }
}

private fun parseId(input: String): Int? {
    val value = input.trim().removePrefix("0x").removePrefix("0X")
    if (value.isEmpty() || value.length > 8 || value.any { it.digitToIntOrNull(16) == null }) return null
    return value.toLongOrNull(16)?.takeIf { it <= 0xFFFFFFFFL }?.toInt()
}

private fun parseValue(input: String, format: ValueFormat): ByteArray? {
    if (input.isEmpty()) return null
    if (format == ValueFormat.TEXT) return input.toByteArray(Charsets.UTF_8)
    val value = input.filterNot(Char::isWhitespace).removePrefix("0x").removePrefix("0X")
    if (value.isEmpty() || value.length % 2 != 0) return null
    return runCatching {
        ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }.getOrNull()
}
