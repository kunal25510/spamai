/**
 * Sentinel Security Agent - Backend Fallback & MIME Parser Test Suite
 */

const assert = require("assert");
const { parseGmailMessage } = require("../backend/emailParser");
const { fallbackAnalyzeEmail } = require("../backend/server");

console.log("=== Running Sentinel Backend & Parser Tests ===");

// 1. Test Base64Url MIME Body & Link Extraction
const mockGmailMessage = {
    id: "msg_12345",
    snippet: "Preview snippet text",
    payload: {
        headers: [
            { name: "From", value: "Unstop Team <noreply@unstop.com>" },
            { name: "Subject", value: "Your Internship Assessment is Live" },
            { name: "Date", value: "Sat, 24 Oct 2026 10:00:00 GMT" },
            { name: "Authentication-Results", value: "mx.google.com; dkim=pass header.i=@unstop.com; spf=pass" }
        ],
        parts: [
            {
                mimeType: "text/html",
                body: {
                    // Base64URL for: '<p>Click <a href="https://unstop.com/assessment">Start Assessment</a></p>'
                    data: "PHA-Q2xpY2sgPGEgaHJlZj0iaHR0cHM6Ly91bnN0b3AuY29tL2Fzc2Vzc21lbnQiPlN0YXJ0IEFzc2Vzc21lbnQ8L2E-PC9wPg"
                }
            }
        ]
    }
};

const parsed = parseGmailMessage(mockGmailMessage);
assert.strictEqual(parsed.id, "msg_12345");
assert.strictEqual(parsed.from, "Unstop Team <noreply@unstop.com>");
assert.strictEqual(parsed.auth.spf, "pass", "SPF should be pass");
assert.strictEqual(parsed.auth.dkim, "pass", "DKIM should be pass");
assert.strictEqual(parsed.urls.length, 1, "Should extract 1 URL");
assert.strictEqual(parsed.urls[0].href, "https://unstop.com/assessment");
assert.strictEqual(parsed.urls[0].text, "Start Assessment");
assert.ok(parsed.bodyText.includes("Start Assessment"), "Body text should include anchor text");

console.log("[PASS] MIME parsing, base64url decoding, and link extraction verified.");

// 2. Test Mismatched / Deceptive Links Extraction
const mockSpoofedMessage = {
    id: "msg_spoofed",
    payload: {
        headers: [
            { name: "From", value: "Google Support <support@attacker-host.top>" },
            { name: "Subject", value: "Account alert" },
            { name: "Received-SPF", value: "fail (google.com: domain does not designate IP)" }
        ],
        parts: [
            {
                mimeType: "text/html",
                body: {
                    // '<a href="http://evil-site.xyz/login">https://myaccount.google.com</a>'
                    data: "PGEgaHJlZj0iaHR0cDovL2V2aWwtc2l0ZS54eXovbG9naW4iPmh0dHBzOi8vbXlhY2NvdW50Lmdvb2dsZS5jb208L2E-"
                }
            }
        ]
    }
};

const parsedSpoof = parseGmailMessage(mockSpoofedMessage);
assert.strictEqual(parsedSpoof.auth.spf, "fail", "SPF should be fail");
assert.strictEqual(parsedSpoof.urls[0].href, "http://evil-site.xyz/login");
assert.strictEqual(parsedSpoof.urls[0].text, "https://myaccount.google.com");

console.log("[PASS] Spoofed email parsing and authentication failure extraction verified.");

// 3. Test Fallback Security Engine (When AI service is offline or timing out)
const fallbackUnstop = fallbackAnalyzeEmail({
    from: "Unstop <noreply@unstop.com>",
    subject: "Your assessment is live",
    bodyText: "Login to your dashboard to begin your test.",
    auth: { spf: "pass", dkim: "pass" }
});
assert.strictEqual(fallbackUnstop.category, "LEGITIMATE");
assert.strictEqual(fallbackUnstop.final_risk, "LOW");
console.log("[PASS] Fallback engine: Unstop legitimate notification preserved.");

const fallbackHarvesting = fallbackAnalyzeEmail({
    from: "Bank Support <admin@unverified.org>",
    subject: "Mandatory verification",
    bodyText: "Reply with your OTP and password immediately.",
    auth: { spf: "none", dkim: "none" }
});
assert.strictEqual(fallbackHarvesting.category, "PHISHING");
assert.strictEqual(fallbackHarvesting.final_risk, "HIGH");
console.log("[PASS] Fallback engine: Credential harvesting flagged as PHISHING.");

const fallbackSpam = fallbackAnalyzeEmail({
    from: "Promo Deals <deals@marketing.com>",
    subject: "Clearance sale 90% discount",
    bodyText: "Limited time discount on shoes. Click to unsubscribe.",
    auth: { spf: "pass", dkim: "pass" }
});
assert.strictEqual(fallbackSpam.category, "SPAM");
assert.strictEqual(fallbackSpam.final_risk, "LOW");
console.log("[PASS] Fallback engine: Promotional content flagged as SPAM.");

console.log("\nALL BACKEND & PARSER TESTS PASSED SUCCESSFULLY!");
