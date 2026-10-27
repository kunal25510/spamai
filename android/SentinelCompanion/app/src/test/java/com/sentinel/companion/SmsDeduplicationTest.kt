package com.sentinel.companion

import com.sentinel.companion.data.local.SmsEntity
import com.sentinel.companion.data.model.SmsItemDto
import com.sentinel.companion.data.model.SmsSyncPayload
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

/**
 * Unit tests verifying SMS deduplication key generation, multipart assembly,
 * and DTO serialization properties.
 */
class SmsDeduplicationTest {

    @Test
    fun testStableDeduplicationKeyGeneration() {
        val deviceId = "dev_1729750000_abc"
        val providerId = "4201"

        fun generateDedupKey(devId: String, pId: String): String {
            val md = MessageDigest.getInstance("SHA-256")
            val bytes = md.digest("$devId:$pId".toByteArray(Charsets.UTF_8))
            return bytes.joinToString("") { "%02x".format(it) }
        }

        val key1 = generateDedupKey(deviceId, providerId)
        val key2 = generateDedupKey(deviceId, providerId)

        assertEquals("Deduplication key must be deterministic", key1, key2)
        assertEquals(64, key1.length) // SHA-256 hex length
    }

    @Test
    fun testMultipartSmsConcatenation() {
        val segment1 = "Dear Customer, your delivery parcel #US9481"
        val segment2 = " has an incomplete delivery address. Please verify at http://tinyurl.com/usps-fix"

        val assembledBody = segment1 + segment2

        val entity = SmsEntity(
            providerId = "inc_1729750000_99",
            sender = "+18005550199",
            body = assembledBody,
            timestamp = 1729750000000L,
            messageType = "inbox",
            syncStatus = SmsEntity.STATUS_PENDING
        )

        assertEquals(
            "Dear Customer, your delivery parcel #US9481 has an incomplete delivery address. Please verify at http://tinyurl.com/usps-fix",
            entity.body
        )
        assertTrue(entity.body.contains("http://tinyurl.com/usps-fix"))
    }

    @Test
    fun testSmsSyncPayloadMapping() {
        val messages = listOf(
            SmsItemDto(
                providerId = "101",
                sender = "AX-HDFCBK",
                body = "INR 2,500.00 debited from a/c **1234 on 24-OCT-26.",
                timestamp = 1729750000000L,
                messageType = "inbox"
            ),
            SmsItemDto(
                providerId = "102",
                sender = "VK-ALERT",
                body = "Your PAN card is blocked. Click http://kyc-update.xyz to avoid deactivation.",
                timestamp = 1729750010000L,
                messageType = "inbox"
            )
        )

        val payload = SmsSyncPayload(
            permissionState = "GRANTED",
            messages = messages
        )

        assertEquals("GRANTED", payload.permissionState)
        assertEquals(2, payload.messages.size)
        assertEquals("AX-HDFCBK", payload.messages[0].sender)
        assertEquals("VK-ALERT", payload.messages[1].sender)
    }
}
