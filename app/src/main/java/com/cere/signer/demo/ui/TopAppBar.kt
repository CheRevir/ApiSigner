package com.cere.signer.demo.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Preview
import com.cere.signer.demo.ui.theme.AppTheme

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TopAppBar(
    title: String,
    navigationIcon: ImageVector? = null,
    modifier: Modifier = Modifier,
    subTile: String? = null,
    colors: TopAppBarColors = TopAppBarDefaults.topAppBarColors(),
    onNavigationClick: () -> Unit = {},
) {
    CenterAlignedTopAppBar(
        title = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (subTile?.isNotEmpty() == true) {
                    Text(
                        text = subTile,
                        maxLines = 1,
                        overflow = TextOverflow.StartEllipsis,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        },
        navigationIcon = navigationIcon?.let { icon -> {
            IconButton(onClick = onNavigationClick) {
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = colors.navigationIconContentColor
                )
            }
        } } ?: {},
        colors = colors,
        modifier = modifier
    )
}

@Preview("Top App Bar", showSystemUi = true)
@Composable
private fun TopAppBarPreview() {
    AppTheme {
        TopAppBar(
            title = stringResource(android.R.string.untitled),
        )
    }
}

