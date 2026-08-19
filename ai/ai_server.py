from flask import Flask, request, jsonify
import joblib
import os
from security_rules import extract_facts, forward_chain
from bayes_risk import calculate_bayes_risk
from fuzzy_risk import calculate_fuzzy_risk

app = Flask(__name__)

# ==========================================
# LOAD MODEL
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run train_model.py first.")

model = joblib.load(MODEL_PATH)


# ==========================================
# PREDICTION API
# ==========================================

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json or {}
    email_text = data.get("text", "")

    if not email_text:
        return jsonify({"error": "Email text is required"}), 400

    # ======================================
    # 1. MACHINE LEARNING
    # ======================================
    prediction = model.predict([email_text])[0]
    probabilities = model.predict_proba([email_text])[0]
    classes = list(model.classes_)
    phish_idx = classes.index("phishing") if "phishing" in classes else 0
    phish_prob = round(probabilities[phish_idx] * 100, 2)
    confidence = max(probabilities) * 100

    # ======================================
    # 2. KNOWLEDGE-BASED AGENT
    # ======================================
    facts = extract_facts(email_text)
    derived_facts = forward_chain(facts)
    rule_phishing = "phishing" in derived_facts

    # ======================================
    # 3. BAYESIAN RISK
    # ======================================
    bayes_risk = calculate_bayes_risk(derived_facts)
    bayes_score = round(bayes_risk * 100, 2)

    # ======================================
    # 4. MACHINE LEARNING RISK
    # ======================================
    ml_risk = phish_prob

    # ======================================
    # 5. FUZZY RISK
    # ======================================
    fuzzy_score, fuzzy_level = calculate_fuzzy_risk(
        ml_risk,
        bayes_score,
        rule_phishing
    )

    # ======================================
    # 6. FINAL RISK - COMBINED AI DECISION
    # ======================================
    rule_score = 100 if rule_phishing else 0

    weighted_average = (
        (ml_risk * 0.40) +
        (bayes_score * 0.30) +
        (fuzzy_score * 0.20) +
        (rule_score * 0.10)
    )

    final_score = round(weighted_average, 2)

    # Determine final risk level
    is_legit = "legitimate_notification" in derived_facts or ("trusted_service" in derived_facts and not rule_phishing)
    has_phishing_evidence = rule_phishing or "credential_phishing" in derived_facts or "financial_phishing" in derived_facts

    if (has_phishing_evidence or (final_score >= 50 and not is_legit) or (ml_risk >= 70 and bayes_score >= 45 and not is_legit)):
        final_risk = "high"
    elif (final_score >= 25 or fuzzy_score >= 30 or bayes_score >= 25 or "suspicious_link" in derived_facts) and not is_legit:
        final_risk = "medium"
    else:
        final_risk = "low"



    # ======================================
    # RESPONSE
    # ======================================
    return jsonify({
        "ml_prediction": prediction,
        "ml_confidence": round(confidence, 2),
        "phishing_probability": phish_prob,
        "facts": list(facts),
        "derived_facts": list(derived_facts),
        "rule_phishing": rule_phishing,
        "bayes_risk": bayes_score,
        "fuzzy_score": fuzzy_score,
        "fuzzy_level": fuzzy_level,
        "final_score": final_score,
        "final_risk": final_risk
    })


# ==========================================
# HOME
# ==========================================

@app.route("/", methods=["GET"])
def home():
    return "AI Security Server Running"


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000
    )