from flask import Flask, request, jsonify
import warnings
warnings.filterwarnings("ignore")
import joblib
import os
from security_rules import extract_facts, forward_chain
from bayes_risk import calculate_bayes_risk
from fuzzy_risk import calculate_fuzzy_risk
from url_analyzer import analyze_url
from message_rules import analyze_general_message, analyze_job_offer, analyze_github_linkedin

app = Flask(__name__)

# ==========================================
# LOAD MODEL
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run train_model.py first.")

model = joblib.load(MODEL_PATH)


def process_email_text(email_text):
    if not email_text:
        return {
            "ml_prediction": "safe",
            "ml_confidence": 0,
            "phishing_probability": 0,
            "facts": [],
            "derived_facts": [],
            "rule_phishing": False,
            "bayes_risk": 0,
            "fuzzy_score": 0,
            "fuzzy_level": "LOW",
            "final_score": 0,
            "final_risk": "low"
        }

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

    return {
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
    }


def analyze_email_unified(email_text):
    res = process_email_text(email_text)
    derived = res.get("derived_facts", [])
    facts = res.get("facts", [])
    ml_prob = res.get("phishing_probability", 0)
    score = int(round(res.get("final_score", 0)))
    risk_level = res.get("final_risk", "low").upper()

    reasons = []
    if "credential_phishing" in derived:
        reasons.append("Credential phishing pattern: combines suspicious link with password/login request.")
    elif "asks_password" in facts:
        reasons.append("Prompts recipient for password, credentials, or login confirmation.")

    if "financial_phishing" in derived:
        reasons.append("Financial phishing pattern: combines monetary scam lure with link or password request.")
    elif "financial_scam" in facts:
        reasons.append("Promises lottery winnings, prize rewards, or cash payouts.")

    if "suspicious_email" in derived or ("urgent_language" in facts and "account_threat" in facts):
        reasons.append("High-pressure coercion: combines urgent deadlines with account suspension threats.")
    elif "urgent_language" in facts:
        reasons.append("Uses urgent or coercive phrasing to pressure immediate action.")
    elif "account_threat" in facts:
        reasons.append("Threatens account deactivation, block, or penalties.")

    if "suspicious_link" in facts:
        reasons.append("Contains suspicious, shortened, or unverified web links.")

    if ml_prob >= 60:
        reasons.append(f"Machine learning model flagged statistical scam patterns ({ml_prob}% probability).")

    if "legitimate_notification" in derived or ("trusted_service" in facts and not res.get("rule_phishing")):
        reasons.append("Matches verified sender pattern from recognized provider (e.g. Google, IPPB).")

    if not reasons:
        reasons.append("No typical phishing indicators, credential traps, or urgent threats detected.")

    if risk_level == "HIGH":
        msg = "High risk: Email contains strong indicators of credential theft, urgency coercion, or fraud."
    elif risk_level == "MEDIUM":
        msg = "Medium risk: Caution advised due to embedded links, urgency, or unfamiliar requests."
    else:
        msg = "Low risk: Email appears routine with no severe phishing or threat indicators detected."

    return {
        "risk_level": risk_level,
        "risk_score": score,
        "reasons": reasons,
        "message": msg,
        "analysis_type": "email",
        "details": {
            "ml_probability": ml_prob,
            "bayes_risk": res.get("bayes_risk"),
            "fuzzy_score": res.get("fuzzy_score"),
            "rule_phishing": res.get("rule_phishing"),
            "disclaimer": "Hybrid AI check (ML + Bayesian + Fuzzy + Heuristics). Never share passwords via email."
        }
    }


# ==========================================
# UNIFIED MULTI-MODE ANALYSIS API
# ==========================================

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json or {}
    mode = data.get("type", "message").lower()
    text = data.get("text", "")
    url = data.get("url", "")

    target_input = url if (mode == "url" and url) else text
    if not target_input and mode == "url" and text:
        target_input = text

    if not target_input or not target_input.strip():
        return jsonify({"error": "Please provide input text or a URL to analyze."}), 400

    if len(target_input) > 20000:
        return jsonify({"error": "Input length exceeds the 20,000 characters limit."}), 400

    if mode == "url":
        result = analyze_url(target_input)
    elif mode == "job":
        result = analyze_job_offer(target_input)
    elif mode == "github_linkedin":
        result = analyze_github_linkedin(target_input)
    elif mode == "email":
        result = analyze_email_unified(target_input)
    elif mode in ["message", "messages"]:
        result = analyze_general_message(target_input)
    else:
        return jsonify({"error": f"Unsupported analysis mode: {mode}"}), 400

    return jsonify(result)


# ==========================================
# LEGACY EMAIL PREDICTION APIs (Preserved)
# ==========================================

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json or {}
    email_text = data.get("text", "")

    if not email_text:
        return jsonify({"error": "Email text is required"}), 400

    result = process_email_text(email_text)
    return jsonify(result)


@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    data = request.json or {}
    items = data.get("items", [])

    results = []
    for item in items:
        item_id = item.get("id")
        text = item.get("text", "")
        res = process_email_text(text)
        res["id"] = item_id
        results.append(res)

    return jsonify({"results": results})


# ==========================================
# HOME & HEALTH
# ==========================================

@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def home():
    return jsonify({"status": "ok", "message": "AI Security Server Running"})


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000,
        threaded=True
    )