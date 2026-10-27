package com.sentinel.companion.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface SmsDao {

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(sms: SmsEntity): Long

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertAll(list: List<SmsEntity>): List<Long>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertOrUpdateAll(list: List<SmsEntity>): List<Long>

    @Query("UPDATE pending_sms SET syncStatus = 'PENDING'")
    suspend fun markAllPending(): Int

    @Query("SELECT * FROM pending_sms WHERE syncStatus = 'PENDING' ORDER BY timestamp ASC LIMIT :limit")
    suspend fun getPendingSms(limit: Int = 50): List<SmsEntity>

    @Query("SELECT * FROM pending_sms WHERE syncStatus = 'PENDING' ORDER BY timestamp ASC LIMIT :limit")
    suspend fun getPendingMessages(limit: Int = 50): List<SmsEntity>

    @Query("UPDATE pending_sms SET syncStatus = 'SYNCED' WHERE id IN (:ids)")
    suspend fun markSynced(ids: List<String>)

    @Query("UPDATE pending_sms SET syncStatus = 'SYNCED' WHERE id IN (:ids)")
    suspend fun markAsSynced(ids: List<String>)

    @Query("UPDATE pending_sms SET syncStatus = 'FAILED', retryCount = retryCount + 1 WHERE id IN (:ids)")
    suspend fun markFailed(ids: List<String>)

    @Query("SELECT COUNT(*) FROM pending_sms WHERE syncStatus = 'PENDING'")
    suspend fun getPendingCount(): Int

    @Query("SELECT COUNT(*) FROM pending_sms WHERE syncStatus = 'PENDING'")
    suspend fun countPending(): Int

    @Query("SELECT COUNT(*) FROM pending_sms WHERE syncStatus = 'SYNCED'")
    suspend fun getSyncedCount(): Int

    @Query("DELETE FROM pending_sms WHERE syncStatus = 'SYNCED' AND timestamp < :cutoffTimestamp")
    suspend fun deleteSyncedOlderThan(cutoffTimestamp: Long): Int

    @Query("DELETE FROM pending_sms WHERE syncStatus = 'SYNCED'")
    suspend fun clearSyncedMessages(): Int

    @Query("SELECT * FROM pending_sms ORDER BY timestamp DESC")
    suspend fun getAllMessages(): List<SmsEntity>

    @Query("SELECT * FROM pending_sms ORDER BY timestamp DESC LIMIT :limit")
    suspend fun getRecentMessages(limit: Int = 100): List<SmsEntity>

    @Query("DELETE FROM pending_sms WHERE id = :id")
    suspend fun deleteById(id: String): Int

    @Query("DELETE FROM pending_sms")
    suspend fun clearAll()
}
