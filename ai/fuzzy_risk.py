def calculate_fuzzy_risk(ml_risk, bayes_risk, rule_phishing):
    score = (
        ml_risk * 0.45
        + bayes_risk * 0.35
        + (100 if rule_phishing else 0) * 0.20
    )

    if score >= 65:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return round(score, 2), level