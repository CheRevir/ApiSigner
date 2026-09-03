package com.cere.signer.demo.ui

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalInspectionMode
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.rememberMultiplePermissionsState

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun FilePermissionEffect(onPermissionChanged: () -> Unit = {}) {
    if (LocalInspectionMode.current) return

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        val context = LocalContext.current
        val settingsLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { onPermissionChanged() }

        LaunchedEffect(Unit) {
            if (!Environment.isExternalStorageManager()) {
                val appSettings = Intent(
                    Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                    Uri.parse("package:${context.packageName}"),
                )
                runCatching { settingsLauncher.launch(appSettings) }
                    .onFailure {
                        settingsLauncher.launch(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                    }
            }
        }
    } else {
        val permissions = buildList {
            add(Manifest.permission.READ_EXTERNAL_STORAGE)
            if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.Q) {
                add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            }
        }
        val permissionState = rememberMultiplePermissionsState(permissions) {
            onPermissionChanged()
        }
        LaunchedEffect(permissionState.allPermissionsGranted) {
            if (!permissionState.allPermissionsGranted) permissionState.launchMultiplePermissionRequest()
        }
    }
}
