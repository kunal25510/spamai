"""
Sentinel AI Security Agent - Universal Regression & Adversarial Test Suite
Covers all requirements from Section 10:
- Popular websites legitimate
- Small and previously unseen domains legitimate
- College notices, internships, competitions, job notifications
- Legitimate login, OTP, and password reset notifications
- Legitimate promotional offers and newsletters
- Realistic phishing and brand impersonation examples
- Suspicious URLs, homoglyphs, and lookalike domains
- Emails with missing authentication headers (graceful handling)
- Malformed and empty messages
- Adversarial pairs (similar subjects, contrasting sender identity & intent)
- User trust and block domain overrides
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ai"))

from ai_server import process_email
from domain_reputation import reputation_store, detect_lookalike_domain


class TestSentinelUniversalPipeline(unittest.TestCase):

    # =========================================================================
    # 1. Legitimate Messages from Popular Websites
    # =========================================================================
    def test_popular_unstop_internship(self):
        email = {
            "from": "Unstop Opportunities <noreply@unstop.com>",
            "subject": "Your Unstop Internship Application was received",
            "snippet": "Click here to login to your dashboard and view hiring status.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://unstop.com/internships/application-status", "text": "View Status"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")
        self.assertLessEqual(res["final_score"], 25)

    def test_popular_github_pull_request(self):
        email = {
            "from": "GitHub <notifications@github.com>",
            "subject": "[antigravity-ide/sentinel] Pull request #18 merged into main",
            "snippet": "kunal merged 3 commits into main from feature-branch.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://github.com/antigravity-ide/sentinel/pull/18", "text": "View Pull Request"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # =========================================================================
    # 2. Legitimate Messages from Small & Previously Unseen Domains
    # =========================================================================
    def test_small_business_invoice_unseen_domain(self):
        # Local design studio from an unfamiliar domain
        email = {
            "from": "Billing Team <invoices@sunrise-digital-studio.in>",
            "subject": "Invoice INV-2026-089 for website redesign project",
            "snippet": "Please find attached your invoice for Phase 1 milestone deliverables.",
            "auth": {"spf": "pass", "dkim": "none"},
            "urls": [{"href": "https://sunrise-digital-studio.in/client-portal", "text": "Client Portal"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    def test_independent_developer_newsletter_unseen_domain(self):
        email = {
            "from": "Alex Rivera <alex@rivera-tech-dispatch.me>",
            "subject": "Issue #42: Modern caching strategies for microservices",
            "snippet": "In this week's edition, we explore distributed Redis locks and cache stampede prevention.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://rivera-tech-dispatch.me/posts/caching-strategies", "text": "Read online"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # =========================================================================
    # 3. College Notices, Competitions & Job Notifications
    # =========================================================================
    def test_college_exam_timetable(self):
        email = {
            "from": "Examination Cell <dean.academics@iitd.ac.in>",
            "subject": "Final Semester Examination Timetable Nov-Dec 2026",
            "snippet": "The timetable for end-term examination has been published on student portal.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://academics.iitd.ac.in/portal/timetable", "text": "View Timetable"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # =========================================================================
    # 4. Legitimate Login, OTP & Password Reset Emails
    # =========================================================================
    def test_google_security_login_alert(self):
        email = {
            "from": "Google <no-reply@accounts.google.com>",
            "subject": "Security alert: New sign-in to your Google Account",
            "snippet": "Your account was accessed from Chrome on Windows. If this was you, no action is needed.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://myaccount.google.com/notifications", "text": "Review activity"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    def test_genuine_otp_verification(self):
        email = {
            "from": "India Post Payments Bank <alerts@ippbonline.com>",
            "subject": "OTP for Savings Account Verification",
            "snippet": "Your one-time password (OTP) is 692014. It is valid for 10 minutes. Do not share with anyone.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": []
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # =========================================================================
    # 5. Legitimate Promotional Offers & Newsletters
    # =========================================================================
    def test_legitimate_newsletter_promotional(self):
        email = {
            "from": "Coursera Highlights <updates@coursera.org>",
            "subject": "Explore top AI and Data Science programs with 25% off",
            "snippet": "Advance your career with accredited university certificates. Unsubscribe at any time.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://www.coursera.org/promo/fall-2026", "text": "Explore Programs"}]
        }
        res = process_email(email)
        # Promotional newsletters without phishing threats are SPAM or LEGITIMATE
        self.assertIn(res["category"], ["LEGITIMATE", "SPAM"])
        self.assertEqual(res["final_risk"], "LOW")

    # =========================================================================
    # 6. Realistic Phishing & Brand Impersonation
    # =========================================================================
    def test_display_name_brand_impersonation(self):
        email = {
            "from": "Google Security Team <support@crypto-free-bonus.xyz>",
            "subject": "Critical Security Alert: Password compromised",
            "snippet": "Google detected an unknown login from Russia. Click here to confirm your password.",
            "auth": {"spf": "fail", "dkim": "fail"},
            "urls": [{"href": "http://crypto-free-bonus.xyz/google-login", "text": "Confirm Password"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")
        self.assertGreaterEqual(res["final_score"], 75)

    # =========================================================================
    # 7. Suspicious URLs, Homoglyphs & Lookalike Domains
    # =========================================================================
    def test_lookalike_domain_paypal(self):
        is_lookalike, info = detect_lookalike_domain("paypa1.com")
        self.assertTrue(is_lookalike)
        self.assertEqual(info["target_brand"], "paypal.com")

        email = {
            "from": "PayPal Security <service@paypa1.com>",
            "subject": "Account suspension notice",
            "snippet": "Confirm your billing information to unlock your PayPal wallet.",
            "auth": {"spf": "neutral", "dkim": "none"},
            "urls": [{"href": "https://paypa1.com/login", "text": "Unlock Account"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")

    def test_mismatched_url_deception(self):
        email = {
            "from": "Campus Recruit <career@student-placement.com>",
            "subject": "Unstop Internship Shortlist",
            "snippet": "Click the link below to access your internship dashboard.",
            "auth": {"spf": "neutral", "dkim": "none"},
            "urls": [{
                "href": "http://evil-phish-collector.ru/unstop-login",
                "text": "https://unstop.com/internships/dashboard"
            }]
        }
        res = process_email(email)
        self.assertIn(res["category"], ["PHISHING", "NEEDS REVIEW"])

    # =========================================================================
    # 8. Emails with Missing Authentication Headers (Neutral, NOT Flagged)
    # =========================================================================
    def test_missing_auth_headers_on_legitimate_sender(self):
        # Independent community clinic with no SPF or DKIM configured
        email = {
            "from": "Community Health Center <appointments@cityclinic.org>",
            "subject": "Confirmation of your annual checkup on Thursday at 3 PM",
            "snippet": "Your appointment with Dr. Gupta is confirmed. Please arrive 10 minutes early.",
            "auth": {"spf": "none", "dkim": "none"},
            "urls": []
        }
        res = process_email(email)
        # Missing auth alone must NEVER flag an ordinary email as phishing
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    # =========================================================================
    # 9. Malformed and Empty Messages
    # =========================================================================
    def test_empty_email_text(self):
        res = process_email({"text": ""})
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_score"], 0)

    # =========================================================================
    # 10. ADVERSARIAL PAIRS (Similar Subjects, Divergent Identity/Intent)
    # =========================================================================

    # Pair A: Unstop Internship Notice vs Lookalike Unstop Fee Phishing
    def test_adversarial_pair_1_legitimate(self):
        email = {
            "from": "Unstop Team <noreply@unstop.com>",
            "subject": "Action Required: Complete your Round 2 assessment for Software Intern",
            "snippet": "Congratulations! Your application has been shortlisted. Login to Unstop to begin.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://unstop.com/assessment/start", "text": "Start Assessment"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    def test_adversarial_pair_1_phishing(self):
        email = {
            "from": "Unstop Careers <careers@unslop.com>",  # Lookalike unslop.com!
            "subject": "Action Required: Complete your Round 2 assessment for Software Intern",
            "snippet": "Congratulations! Pay mandatory registration fee of INR 2,500 to confirm interview.",
            "auth": {"spf": "neutral", "dkim": "none"},
            "urls": [{"href": "http://unslop.com/pay-fee", "text": "Pay Registration Fee"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")

    # Pair B: Bank Monthly Statement vs Phishing Account Verification
    def test_adversarial_pair_2_legitimate(self):
        email = {
            "from": "HDFC Bank Alerts <alerts@hdfcbank.com>",
            "subject": "Monthly account statement for account ending in 8901",
            "snippet": "Your monthly e-statement is attached. Password is your date of birth followed by PAN.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": []
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

    def test_adversarial_pair_2_phishing(self):
        email = {
            "from": "HDFC Security <security@hdfc-update.xyz>",
            "subject": "Monthly account statement for account ending in 8901",
            "snippet": "Account blocked due to KYC non-compliance. Sign in at http://hdfc-update.xyz/login immediately.",
            "auth": {"spf": "fail", "dkim": "fail"},
            "urls": [{"href": "http://hdfc-update.xyz/login", "text": "Sign in to KYC"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")

    # =========================================================================
    # 11. Specific Real-World Scenarios from User Incident
    # =========================================================================
    def test_unstop_news_domain_alignment(self):
        """Validates that display name 'Jia from Unstop' on 'unstop.news' is NOT brand impersonation."""
        email = {
            "from": "Jia from Unstop <noreply@unstop.news>",
            "subject": "Exclusive Opportunities for You",
            "snippet": "Leading tech firms are hiring software interns. Apply before the deadline.",
            "body": "Explore coding contests, hiring challenges, and internships at leading companies.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://delivery.unstop.news/wf/click?upn=12345", "text": "Explore Internships"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")
        self.assertNotIn("brand_impersonation", res["derived_facts"])
        self.assertNotIn("deceptive_subdomain", res["derived_facts"])
        # Verify evidence does not claim brand impersonation or imitation
        for ev in res["evidence"]:
            self.assertNotEqual(ev.get("type"), "BRAND_IMPERSONATION")
            self.assertNotEqual(ev.get("type"), "DECEPTIVE_SUBDOMAIN")

    def test_render_nodejs_anchor_text(self):
        """Validates that technical term 'Node.js' as anchor text is NOT flagged as mismatched URL."""
        email = {
            "from": "Render <no-reply@render.com>",
            "subject": "Security Advisory: Node.js runtime update available",
            "snippet": "We have updated the default Node.js LTS version on your web services.",
            "body": "Please read our security documentation regarding Node.js runtime compatibility.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://render.com/docs/node-security", "text": "Node.js"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertNotIn("mismatched_url", res["derived_facts"])

    def test_kaggle_google_storage_url(self):
        """Validates that legitimate multi-domain property 'storage.googleapis.com' is not deceptive."""
        email = {
            "from": "Kaggle <no-reply@kaggle.com>",
            "subject": "New response in Kaggle Discussions",
            "snippet": "A new reply was posted to your notebook discussion thread.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://storage.googleapis.com/kaggle-forum-attachments/chart.png", "text": "Attachment"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertNotIn("deceptive_subdomain", res["derived_facts"])

    def test_unverified_domain_without_malicious_intent(self):
        """Validates that display name differences on unverified domains do NOT falsely assert impersonation."""
        email = {
            "from": "Northwestern Conference <notifications@eventdispatch.org>",
            "subject": "Keynote presentation schedule for Wednesday",
            "snippet": "Here is the speaking schedule for the upcoming regional conference.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": [{"href": "https://eventdispatch.org/schedule", "text": "Schedule"}]
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertNotIn("brand_impersonation", res["derived_facts"])
        # Should have DOMAIN_UNVERIFIED evidence reporting ownership unverified
        has_unverified_ev = any(ev.get("type") == "DOMAIN_UNVERIFIED" for ev in res["evidence"])
        self.assertTrue(has_unverified_ev)

    # =========================================================================
    # 12. User Domain Trust & Block Overrides (Scoped & Reversible)
    # =========================================================================
    def test_user_trust_override(self):
        test_domain = "unknown-small-consultancy.co"
        reputation_store.set_user_rule(test_domain, "TRUSTED", "Known client")

        email = {
            "from": f"Partner <contact@{test_domain}>",
            "subject": "Contract agreement documents",
            "snippet": "Here is the revised project scope.",
            "auth": {"spf": "none", "dkim": "none"},
            "urls": []
        }
        res = process_email(email)
        self.assertEqual(res["category"], "LEGITIMATE")
        self.assertEqual(res["final_risk"], "LOW")

        # Clean up
        reputation_store.set_user_rule(test_domain, "NONE")

    def test_user_block_override(self):
        test_domain = "persistent-telemarketer.net"
        reputation_store.set_user_rule(test_domain, "BLOCKED", "Spam sender")

        email = {
            "from": f"Sales <deals@{test_domain}>",
            "subject": "Special offer for your company",
            "snippet": "Exclusive pricing on office supplies.",
            "auth": {"spf": "pass", "dkim": "pass"},
            "urls": []
        }
        res = process_email(email)
        self.assertEqual(res["category"], "PHISHING")
        self.assertEqual(res["final_risk"], "HIGH")

        # Clean up
        reputation_store.set_user_rule(test_domain, "NONE")

    def test_trust_override_isolation(self):
        """Verifies that whitelisting one domain does NOT whitelist other domains."""
        domain_a = "specific-vendor-a.com"
        domain_b = "untrusted-attacker-b.xyz"

        reputation_store.set_user_rule(domain_a, "TRUSTED", "Scoped trust")

        # Sender from domain B with threat payload must NOT inherit trust
        email_b = {
            "from": f"Support <security@{domain_b}>",
            "subject": "Your account is locked",
            "snippet": "Send us your password to unlock.",
            "auth": {"spf": "fail", "dkim": "fail"},
            "urls": [{"href": f"http://{domain_b}/login", "text": "Login"}]
        }
        res_b = process_email(email_b)
        self.assertEqual(res_b["category"], "PHISHING")
        self.assertEqual(res_b["final_risk"], "HIGH")

        reputation_store.set_user_rule(domain_a, "NONE")


if __name__ == "__main__":
    unittest.main()
