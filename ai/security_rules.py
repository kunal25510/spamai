import re

def extract_facts(email):
    email_text = email.lower()
    facts = set()

    # Trusted services / official notifications
    trusted_patterns = [
        r"google\.com", r"sign in with google", r"google account",
        r"india post", r"post office savings account", r"ippb",
        r"zerossl", r"orbit-strategies\.co", r"mahasarathi",
        r"linkedin\.com", r"spotify", r"canva", r"adobe", r"unstop", r"codecademy"
    ]
    if any(re.search(pattern, email_text) for pattern in trusted_patterns):
        facts.add("trusted_service")

    # Suspicious link detection (http links, external domain links, raw IPs, suspicious query links)
    link_patterns = [
        r"http://[^\s]+", r"bit\.ly", r"tinyurl\.com", r"fake-", r"suspicious-",
        r"click\s+here", r"login\s+link", r"follow\s+the\s+link", r"access\s+document\s*:"
    ]
    if any(re.search(pattern, email_text) for pattern in link_patterns):
        facts.add("suspicious_link")

    # Password / Credential harvesting / Login / Account Access request
    cred_words = [
        "password", "login", "sign in", "sign-in", "signin", "credentials",
        "confirm access", "verify account", "confirm your account", "verify your password",
        "enter your login", "send your otp", "2fa", "passcode", "account access",
        "access document", "waiting for confirmation"
    ]
    if any(word in email_text for word in cred_words):
        facts.add("asks_password")

    # Urgent threat language
    urgent_words = [
        "urgent!", "immediately", "act now", "final warning", "within 24 hours",
        "account will be blocked", "account suspended", "deactivated", "locked"
    ]
    if any(word in email_text for word in urgent_words):
        facts.add("urgent_language")

    # Account threat / action
    threat_words = [
        "account will be blocked", "account will be suspended", "locked",
        "deactivated", "compromised", "prosecution"
    ]
    if any(word in email_text for word in threat_words):
        facts.add("account_threat")

    # Financial / Scam reward keywords
    scam_words = [
        "lottery", "won 50000", "free money", "processing fee", "claim your prize", "pay a small fee"
    ]
    if any(word in email_text for word in scam_words):
        facts.add("financial_scam")

    return facts


def forward_chain(facts):
    new_facts = set(facts)
    changed = True

    while changed:
        changed = False

        # Legitimate service protection rule (only if no credential requests or suspicious links)
        if "trusted_service" in new_facts and "asks_password" not in new_facts and "suspicious_link" not in new_facts and "financial_scam" not in new_facts:
            if "legitimate_notification" not in new_facts:
                new_facts.add("legitimate_notification")
                changed = True

        # Rule 1: Link + Password Request / Sign-in Request => Credential Phishing
        if "suspicious_link" in new_facts and "asks_password" in new_facts:
            if "credential_phishing" not in new_facts:
                new_facts.add("credential_phishing")
                changed = True

        # Rule 2: Urgency + Threat => Suspicious Email
        if "urgent_language" in new_facts and "account_threat" in new_facts:
            if "suspicious_email" not in new_facts:
                new_facts.add("suspicious_email")
                changed = True

        # Rule 3: Financial Scam + Password/Link => High Fraud Risk
        if "financial_scam" in new_facts and ("asks_password" in new_facts or "suspicious_link" in new_facts):
            if "financial_phishing" not in new_facts:
                new_facts.add("financial_phishing")
                changed = True

        # Rule 4: Master Phishing Deduction
        if (
            "credential_phishing" in new_facts
            or "suspicious_email" in new_facts
            or "financial_phishing" in new_facts
        ):
            if "phishing" not in new_facts:
                new_facts.add("phishing")
                changed = True

    return new_facts



if __name__ == "__main__":
    test_email = "IPPB Adds convenience to your Post Office Savings Account."
    facts = extract_facts(test_email)
    print("Extracted Facts:", facts)
    result = forward_chain(facts)
    print("Derived Facts:", result)
