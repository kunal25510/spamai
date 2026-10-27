"""
Sentinel Security Agent - Fuzzy Logic Multi-Criteria Risk Assessment
Evaluates multi-criteria risk across ML probability, Bayesian risk, and rule evidence
using fuzzy membership functions and linguistic inference rules.
"""

def _trimf(x, a, b, c):
    """Triangular membership function."""
    if x <= a or x >= c:
        return 0.0
    elif a < x <= b:
        return (x - a) / (b - a) if b > a else 1.0
    else:
        return (c - x) / (c - b) if c > b else 1.0

def _trapmf(x, a, b, c, d):
    """Trapezoidal membership function."""
    if x <= a or x >= d:
        return 0.0
    elif b <= x <= c:
        return 1.0
    elif a < x < b:
        return (x - a) / (b - a) if b > a else 1.0
    else:
        return (d - x) / (d - c) if d > c else 1.0


def calculate_fuzzy_risk(ml_threat_percent, bayes_risk_percent, derived_facts):
    """
    Applies fuzzy inference to compute a calibrated composite threat score (0-100)
    and qualitative risk level ('LOW', 'MEDIUM', 'HIGH').
    """
    ml_val = min(max(float(ml_threat_percent), 0.0), 100.0)
    bayes_val = min(max(float(bayes_risk_percent), 0.0), 100.0)

    # 1. Fuzzy Membership: ML Threat Score
    ml_low = _trapmf(ml_val, 0, 0, 25, 45)
    ml_med = _trimf(ml_val, 30, 50, 70)
    ml_high = _trapmf(ml_val, 55, 75, 100, 100)

    # 2. Fuzzy Membership: Bayesian Risk Score
    bayes_low = _trapmf(bayes_val, 0, 0, 20, 35)
    bayes_med = _trimf(bayes_val, 25, 45, 65)
    bayes_high = _trapmf(bayes_val, 50, 70, 100, 100)

    # 3. Rule Evidence Factors
    is_legitimate = "legitimate_communication" in derived_facts or "user_trusted_domain" in derived_facts
    is_phish_threat = (
        "phishing_threat" in derived_facts or
        "financial_phishing" in derived_facts or
        "blocked_threat" in derived_facts or
        "lookalike_domain_detected" in derived_facts
    )
    is_suspicious = "needs_review" in derived_facts or "deceptive_subdomain" in derived_facts

    # 4. Fuzzy Rule Activations (Mamdani min-operator)
    rule_high = max(
        min(ml_high, bayes_high),
        1.0 if is_phish_threat else 0.0,
        min(ml_high, 0.8 if is_suspicious else 0.0)
    )

    rule_med = max(
        min(ml_med, bayes_med),
        min(ml_low, bayes_high) * 0.7,
        min(ml_high, bayes_low) * 0.7,
        0.8 if is_suspicious and not is_phish_threat else 0.0
    )

    rule_low = max(
        min(ml_low, bayes_low),
        1.0 if is_legitimate and not is_phish_threat else 0.0
    )

    # Suppress risk elevation if verified authentic with no malicious indicators
    if is_legitimate and not is_phish_threat and not is_suspicious:
        rule_high = 0.0
        rule_med = min(rule_med, 0.15)
        rule_low = max(rule_low, 0.9)

    # 5. Defuzzification (Weighted Centroid Estimation)
    # Centers of linguistic sets: LOW=15, MEDIUM=50, HIGH=88
    total_weight = rule_low + rule_med + rule_high
    if total_weight <= 0:
        crisp_score = 15.0
    else:
        crisp_score = (
            (rule_low * 15.0) +
            (rule_med * 50.0) +
            (rule_high * 88.0)
        ) / total_weight

    crisp_score = round(min(max(crisp_score, 0.0), 100.0), 2)

    # Qualitative classification
    if crisp_score >= 65.0 or is_phish_threat:
        level = "HIGH"
    elif crisp_score >= 30.0 or is_suspicious:
        level = "MEDIUM"
    else:
        level = "LOW"

    return crisp_score, level