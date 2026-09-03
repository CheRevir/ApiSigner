package com.cere.signer.demo.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.InsertDriveFile
import androidx.compose.material.icons.rounded.AudioFile
import androidx.compose.material.icons.rounded.FileUpload
import androidx.compose.material.icons.rounded.Android
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.painter.Painter
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.rememberVectorPainter
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.cere.signer.demo.model.FileNode
import com.cere.signer.demo.ui.theme.AppTheme
import com.cere.signer.demo.model.FileType

@Composable
fun FileItem(file: FileNode, onClick: () -> Unit = {}) {
    val icon = when (file.type) {
        FileType.FOLDER -> Icons.Rounded.Folder
        FileType.APK -> Icons.Rounded.Android
        FileType.UNKNOW -> Icons.AutoMirrored.Rounded.InsertDriveFile
    }
    FileItem(icon = icon, title = file.name, onClick = onClick)
}

@Composable
fun FileItem(
    title: String,
    icon: ImageVector = Icons.Rounded.FileUpload,
    onClick: () -> Unit = {}
) {
    FileItem(rememberVectorPainter(icon), title, onClick = onClick)
}

@Composable
internal fun FileItem(
    icon: Painter,
    title: String,
    iconTintColor: Color = MaterialTheme.colorScheme.primary,
    titleColor: Color = MaterialTheme.colorScheme.onPrimaryContainer,
    onClick: () -> Unit = {}
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .height(56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp)
    ) {
        Icon(icon, contentDescription = null, tint = iconTintColor)
        Spacer(Modifier.width(8.dp))
        Text(text = title, color = titleColor)
    }
}

@Preview
@Composable
private fun FileItemPreview() {
    AppTheme {
        FileItem(icon = rememberVectorPainter(Icons.Rounded.AudioFile), "File")
    }
}
