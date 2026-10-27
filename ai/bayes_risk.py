"""
Sentinel Security Agent - Calibrated Universal Bayesian Risk Engine
Computes posterior threat probabilities using Bayes' Rule and likelihood ratios
over independent, non-overlapping security evidence across any domain.
"""

def calculate_bayes_risk(facts):
    """
    Computes calibrated Bayesian risk (0.0 to 1.0) using Bayes' Rule and likelihood ratios.
    Never penalizes missing authentication or unfamiliar domains without malicious evidence.
    """
    # Prior probability of malicious email in normal inbox is calibrated at 8%
    prior_prob = 0.08
    prior_odds = prior_prob / (1.0 - prior_prob)

    likelihood_ratio = 1.0

    # 1. User Overrides (Explicit User Decision)
    if "user_trusted_domain" in facts and "auth_failed" not in facts:
        likelihood_ratio *= 0.04
    elif "user_blocked_domain" in facts or "blocked_threat" in facts:
        likelihood_ratio *= 25.0

    # 2. Universal Legitimate Communication & Verified Platforms
    if "legitimate_communication" in facts and "phishing_threat" not in facts:
        likelihood_ratio *= 0.08
    elif "verified_trusted_sender" in facts and "auth_failed" not in facts:
        likelihood_ratio *= 0.10

    # 3. Cryptographic Authentication Evidence
    if "auth_failed" in facts:
        likelihood_ratio *= 5.0
    elif "auth_passed" in facts and "legitimate_communication" not in facts:
        likelihood_ratio *= 0.65
    elif "auth_missing_neutral" in facts:
        # Missing auth alone is NEUTRAL (1.0) and does not increase threat odds
        likelihood_ratio *= 1.0

    # 4. Lookalike & Brand Impersonation Evidence
    if "lookalike_domain_detected" in facts or "lookalike_url_destination" in facts:
        likelihood_ratio *= 15.0
    elif "brand_impersonation" in facts:
        likelihood_ratio *= 8.0

    if "mismatched_reply_to" in facts:
        likelihood_ratio *= 2.5

    # 5. URL Deception Evidence (Takes strongest signal to avoid double-counting)
    if "mismatched_url" in facts:
        likelihood_ratio *= 8.0
    elif "ip_address_url" in facts:
        likelihood_ratio *= 6.0
    elif "deceptive_subdomain" in facts:
        likelihood_ratio *= 5.5
    elif "high_risk_tld" in facts:
        likelihood_ratio *= 2.5
    elif "url_shortener" in facts:
        likelihood_ratio *= 1.4

    # 6. Payload & Intent Evidence
    if "explicit_credential_solicitation" in facts:
        likelihood_ratio *= 12.0
    elif "financial_scam_lure" in facts or "fraudulent_fee_demand" in facts:
        likelihood_ratio *= 6.5
    elif "urgent_threat" in facts:
        likelihood_ratio *= 2.2

    # 7. Commercial Promotion Factor (Shifts probability toward spam, away from phishing)
    if "promotional_content" in facts:
        likelihood_ratio *= 0.70

    # Calculate Posterior Odds & Probability
    posterior_odds = prior_odds * likelihood_ratio
    posterior_prob = posterior_odds / (1.0 + posterior_odds)

    # Bound safely between 0.01 and 0.99
    return round(float(min(max(posterior_prob, 0.01), 0.99)), 4)