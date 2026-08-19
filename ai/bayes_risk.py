def calculate_bayes_risk(facts):
    if not facts or "legitimate_notification" in facts:
        return 0.02

    probability = 0.05

    if "trusted_service" in facts:
        probability = max(0.01, probability - 0.03)

    if "suspicious_link" in facts:
        probability += 0.25

    if "asks_password" in facts:
        probability += 0.20

    if "urgent_language" in facts:
        probability += 0.15

    if "account_threat" in facts:
        probability += 0.15

    if "financial_scam" in facts:
        probability += 0.15

    if "credential_phishing" in facts or "financial_phishing" in facts:
        probability += 0.30

    if "phishing" in facts:
        probability += 0.30

    return min(probability, 0.99)
