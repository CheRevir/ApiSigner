package com.cere.signer.demo.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Search
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
    navigationIcon: ImageVector,
    actionIcon: ImageVector,
    modifier: Modifier = Modifier,
    subTile: String? = null,
    colors: TopAppBarColors = TopAppBarDefaults.topAppBarColors(),
    onNavigationClick: () -> Unit = {},
    onActionClick: () -> Unit = {}
) {
    CenterAlignedTopAppBar(
        title = {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(title, maxLines = 1, overflow = TextOverflow.StartEllipsis)
                if (subTile?.isNotEmpty() == true) {
                    Text(subTile)
                }
            }
        },
        navigationIcon = {
            IconButton(onClick = onNavigationClick) {
                Icon(
                    imageVector = navigationIcon,
                    contentDescription = null,
                    tint = colors.navigationIconContentColor
                )
            }
        },
        actions = {
            IconButton(onClick = onActionClick) {
                Icon(
                    imageVector = actionIcon,
                    contentDescription = null,
                    tint = colors.actionIconContentColor
                )
            }
        },
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
            navigationIcon = Icons.Rounded.Search,
            actionIcon = Icons.Rounded.Add,
        )
    }
}

