"""
Sentinel AI Security Agent - SMS Security Classification Test Suite
Verifies accuracy on SMS specific contexts:
- Legitimate OTPs vs credential solicitation
- Bank transaction alerts vs smishing alerts
- Package delivery notifications vs address/fee scams
- Personal conversations
- Fake KYC / account deactivation threats
- Fraudulent lottery and job fee lures
- Empty and malformed text
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai"))

from ai_server import process_email


class TestSentinelSmsAi(unittest.TestCase):

    # 1. Genuine OTP Notification (DO NOT SHARE)
    def test_genuine_otp_notification(self):
        sms = {
            "from": "Google",
            "body": "G-684920 is your Google verification code. Do not share this code with anyone.",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")
        self.assertLessEqual(res["final_score"], 25)

    # 2. Credential Solicitation / Phishing OTP Request
    def test_credential_solicitation_smishing(self):
        sms = {
            "from": "+18005550192",
            "body": "Security Alert: An unauthorized device tried to login. Reply with your OTP immediately to verify account.",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")
        self.assertGreaterEqual(res["final_score"], 75)

    # 3. Genuine Bank Debit / Credit Alert
    def test_genuine_bank_alert(self):
        sms = {
            "from": "AX-HDFCBK",
            "body": "Acct XX1092 debited by Rs 2,450.00 on 24-Oct-26. UPI Ref 38291049281. Call 18002664332 if not you.",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # 4. Fake KYC Deactivation Smishing
    def test_fake_kyc_smishing(self):
        sms = {
            "from": "+919876543210",
            "body": "Dear customer your SBI bank account and SIM card will be deactivated within 24 hours. Click to update KYC: http://sbi-kyc-service.xyz",
            "urls": [{"href": "http://sbi-kyc-service.xyz", "text": "http://sbi-kyc-service.xyz"}],
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")
        self.assertIn("kyc_account_threat", res["derived_facts"])

    # 5. Genuine Package Delivery Update
    def test_genuine_delivery_update(self):
        sms = {
            "from": "Amazon",
            "body": "Your order #402-9988112 is out for delivery today with associate Rahul. Share PIN 4921 at delivery.",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # 6. Smishing Delivery Address & Fee Scam
    def test_smishing_delivery_scam(self):
        sms = {
            "from": "+18005550188",
            "body": "Your FedEx parcel could not be delivered due to incomplete address. Update address and pay $1.99 redelivery fee at http://fedex-redelivery.xyz/track",
            "urls": [{"href": "http://fedex-redelivery.xyz/track", "text": "http://fedex-redelivery.xyz/track"}],
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")
        self.assertIn("delivery_fee_scam", res["derived_facts"])

    # 7. Personal Conversation SMS
    def test_personal_conversation(self):
        sms = {
            "from": "+919820011223",
            "body": "Hey Kunal, are we still meeting for lunch today at 1? Let me know!",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # 8. Promotional Marketing SMS
    def test_promotional_marketing_sms(self):
        sms = {
            "from": "LM-TRENDZ",
            "body": "Festive Mega Sale! Flat 50% off on all clothing this weekend at Trendz Store. Use code FLASH50 at checkout.",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "SPAM")
        self.assertIn(res["final_risk"], ["LOW", "MEDIUM"])

    # 9. Fraudulent Lottery / Advance Fee Scam
    def test_lottery_fraud_sms(self):
        sms = {
            "from": "+1987654321",
            "body": "Congratulations! You won Rs 25,00,000 in KBC Lucky Draw. Pay processing fee of Rs 5000 to claim your unclaimed prize.",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")
        self.assertIn("financial_phishing", res["derived_facts"])

    # 10. Empty SMS Text
    def test_empty_sms(self):
        sms = {
            "from": "+1234567890",
            "body": "",
            "source": "SMS"
        }
        res = process_email(sms)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_score"], 0)


if __name__ == "__main__":
    unittest.main()
