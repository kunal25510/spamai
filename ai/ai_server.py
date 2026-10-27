"""
Sentinel AI Security Agent - Master Decision Server (Python Flask)
Integrates Machine Learning (4-class), Universal Sender Reputation,
Forward-Chaining Security Rules, Calibrated Bayesian Risk, and Fuzzy Logic.
"""

import os
import json
import joblib
from flask import Flask, request, jsonify

from security_rules import extract_facts, forward_chain
from bayes_risk import calculate_bayes_risk
from fuzzy_risk import calculate_fuzzy_risk
from domain_reputation import reputation_store

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "model_metadata.json")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run train_model.py first.")

model = joblib.load(MODEL_PATH)

model_metadata = {}
if os.path.exists(METADATA_PATH):
    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            model_metadata = json.load(f)
    except Exception:
        pass


def process_email(email_input):
    """
    Evaluates an email using ML, universal reputation, rules, Bayesian likelihood, and fuzzy reasoning.
    email_input can be a structured dictionary or a raw text string.
    """
    if isinstance(email_input, dict):
        email_data = email_input
        email_text = (
            (email_data.get("subject") or "") + " " +
            (email_data.get("snippet") or "") + " " +
            (email_data.get("body") or "") + " " +
            (email_data.get("text") or "")
        ).strip()
    else:
        email_text = str(email_input or "").strip()
        email_data = {"text": email_text}

    if not email_text:
        return {
            "category": "LEGITIMATE",
            "final_risk": "LOW",
            "final_score": 0,
            "confidence": 100.0,
            "evidence": [],
            "reasons": ["Empty or blank message body."],
            "ml_prediction": "legitimate",
            "ml_probabilities": {"legitimate": 1.0, "spam": 0.0, "phishing": 0.0, "suspicious": 0.0},
            "bayes_risk": 0.01,
            "fuzzy_score": 0.0,
            "fuzzy_level": "LOW",
            "facts": [],
            "derived_facts": []
        }

    # ==========================================
    # 1. MACHINE LEARNING (4-CLASS CLASSIFIER)
    # ==========================================
    ml_pred = model.predict([email_text])[0]
    probabilities = model.predict_proba([email_text])[0]
    classes = list(model.classes_)

    ml_probs = {cls: round(float(prob), 4) for cls, prob in zip(classes, probabilities)}
    confidence = round(float(max(probabilities)) * 100, 2)
    phish_prob = round(float(ml_probs.get("phishing", 0.0)) * 100, 2)
    spam_prob = round(float(ml_probs.get("spam", 0.0)) * 100, 2)

    # ==========================================
    # 2. UNIVERSAL REPUTATION & FACT EXTRACTION
    # ==========================================
    facts, evidence_details = extract_facts(email_data)
    derived_facts = forward_chain(facts)

    # ==========================================
    # 3. BAYESIAN RISK INFERENCE
    # ==========================================
    bayes_val = calculate_bayes_risk(derived_facts)
    bayes_score = round(bayes_val * 100, 2)

    # ==========================================
    # 4. FUZZY LOGIC MULTI-CRITERIA RISK
    # ==========================================
    fuzzy_score, fuzzy_level = calculate_fuzzy_risk(
        ml_threat_percent=phish_prob,
        bayes_risk_percent=bayes_score,
        derived_facts=derived_facts
    )

    # ==========================================
    # 5. CALIBRATED AGGREGATION & CATEGORY
    # ==========================================
    raw_reasons = []

    is_legitimate = "legitimate_communication" in derived_facts or "user_trusted_domain" in derived_facts
    has_phish_threat = (
        "phishing_threat" in derived_facts or
        "financial_phishing" in derived_facts or
        "blocked_threat" in derived_facts or
        "lookalike_domain_detected" in derived_facts
    )
    needs_review = (
        "needs_review" in derived_facts or
        "deceptive_subdomain" in derived_facts or
        "mismatched_url" in derived_facts or
        "mismatched_reply_to" in derived_facts
    )
    is_promo_spam = "commercial_spam" in derived_facts

    for ev in evidence_details:
        raw_reasons.append(ev["description"])

    if has_phish_threat or (phish_prob >= 75.0 and not is_legitimate):
        category = "PHISHING"
        final_risk = "HIGH"
        final_score = max(int(round(fuzzy_score)), 80)
        if not raw_reasons:
            raw_reasons.append("Email contains deceptive impersonation, credential harvesting, or fraudulent lures.")
    elif is_legitimate and not has_phish_threat:
        category = "LEGITIMATE"
        final_risk = "LOW"
        final_score = min(int(round(fuzzy_score)), 25)
        if not raw_reasons:
            raw_reasons.append("Benign communication from authentic domain with passing security checks.")
    elif is_promo_spam or (ml_pred == "spam" and spam_prob >= 50.0 and not has_phish_threat):
        category = "SPAM"
        final_risk = "LOW" if fuzzy_score < 40 else "MEDIUM"
        final_score = min(max(int(round(fuzzy_score)), 30), 50)
        if not raw_reasons:
            raw_reasons.append("Promotional marketing material or unsolicited bulk communication.")
    elif needs_review or (confidence < 45.0) or (ml_pred == "suspicious"):
        category = "NEEDS REVIEW"
        final_risk = "MEDIUM"
        final_score = min(max(int(round(fuzzy_score)), 45), 65)
        if not raw_reasons:
            raw_reasons.append("Message contains ambiguous traits or unverified sender links requiring manual review.")
    else:
        # Map from ML prediction
        category_map = {
            "legitimate": "LEGITIMATE",
            "spam": "SPAM",
            "phishing": "PHISHING",
            "suspicious": "NEEDS REVIEW"
        }
        category = category_map.get(ml_pred, "NEEDS REVIEW")
        if category == "LEGITIMATE":
            final_risk = "LOW"
            final_score = min(int(round(fuzzy_score)), 25)
            if not raw_reasons:
                raw_reasons.append("Routine correspondence or benign service notification.")
        elif category == "PHISHING":
            final_risk = "HIGH"
            final_score = max(int(round(fuzzy_score)), 80)
            if not raw_reasons:
                raw_reasons.append("Suspected phishing pattern detected in message structure.")
        elif category == "SPAM":
            final_risk = "LOW"
            final_score = 35
            if not raw_reasons:
                raw_reasons.append("Unsolicited promotional content.")
        else:
            final_risk = "MEDIUM"
            final_score = 50
            if not raw_reasons:
                raw_reasons.append("Uncertain message requiring user attention.")

    # Deduplicate reasons while preserving order
    seen_reasons = set()
    deduped_reasons = []
    for r in raw_reasons:
        if r not in seen_reasons:
            seen_reasons.add(r)
            deduped_reasons.append(r)

    return {
        "category": category,
        "final_risk": final_risk,
        "final_score": final_score,
        "confidence": confidence,
        "evidence": evidence_details,
        "reasons": deduped_reasons,
        "ml_prediction": ml_pred,
        "ml_probabilities": ml_probs,
        "bayes_risk": bayes_score,
        "fuzzy_score": fuzzy_score,
        "fuzzy_level": fuzzy_level,
        "facts": list(facts),
        "derived_facts": list(derived_facts)
    }


# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.route("/predict", methods=["POST"])
def predict():
    data = request.json or {}
    result = process_email(data)
    return jsonify(result)


@app.route("/predict_batch", methods=["POST"])
def predict_batch():
    data = request.json or {}
    items = data.get("items", [])

    results = []
    for item in items:
        item_id = item.get("id")
        res = process_email(item)
        res["id"] = item_id
        results.append(res)

    return jsonify({"results": results})


# Domain Reputation API
@app.route("/api/reputation", methods=["GET"])
def get_reputation():
    data = reputation_store._read_data()
    return jsonify(data)


@app.route("/api/reputation/override", methods=["POST"])
def set_reputation_override():
    payload = request.json or {}
    domain = payload.get("domain", "").strip()
    status = payload.get("status", "NONE").strip().upper()
    notes = payload.get("notes", "").strip()

    if not domain:
        return jsonify({"error": "domain is required"}), 400

    try:
        reputation_store.set_user_rule(domain, status, notes)
        return jsonify({"success": True, "domain": domain, "status": status})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/health", methods=["GET"])
@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "Sentinel AI Security Server",
        "classes": list(model.classes_),
        "metadata": model_metadata.get("metrics", {})
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, threaded=True)