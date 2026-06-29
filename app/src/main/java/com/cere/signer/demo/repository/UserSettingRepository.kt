package com.cere.signer.demo.repository

import com.cere.signer.demo.datastore.UserSettingDataStore
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class UserSettingRepository @Inject constructor(private val dataStore: UserSettingDataStore) {

    val currentPath: Flow<String> = dataStore.currentPath

    suspend fun setCurrentPath(path: String) = dataStore.setCurrentPath(path)
}