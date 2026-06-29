package com.cere.signer.demo.datastore

import android.os.Environment
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject

class UserSettingDataStore @Inject constructor(private val dataStore: DataStore<Preferences>) {

    val currentPath: Flow<String>
        get() = dataStore.data.map { it[stringPreferencesKey(KEY_CURRENT_PATH)] ?: Environment.getExternalStorageDirectory().absolutePath }

    suspend fun setCurrentPath(path: String) {
        dataStore.updateData {
            it.toMutablePreferences().also {
                it[stringPreferencesKey(KEY_CURRENT_PATH)] = path
            }
        }
    }

    companion object {
        private const val KEY_CURRENT_PATH = "currentPath"
    }
}