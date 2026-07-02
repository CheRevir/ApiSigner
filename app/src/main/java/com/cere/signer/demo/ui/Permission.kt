package com.cere.signer.demo.ui

import android.Manifest
import android.os.Build
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalInspectionMode
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.PermissionStatus
import com.google.accompanist.permissions.rememberPermissionState

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun FilePermissionEffect() {
    if (LocalInspectionMode.current) {
        return
    }

    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
        return
    }

    val permissionState = rememberPermissionState(Manifest.permission.MANAGE_EXTERNAL_STORAGE)

    LaunchedEffect(permissionState) {
        val status = permissionState.status
            permissionState.launchPermissionRequest()
    }
}