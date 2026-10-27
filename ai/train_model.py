"""
Sentinel Security Agent - Model Training & Rigorous Multi-Class Evaluation
Trains a TF-IDF + Logistic Regression pipeline on 4 classes:
- legitimate
- spam
- phishing
- suspicious

Reports precision, recall, F1, confusion matrix, per-class false-positive rates,
and explicitly measures legitimate message false positives.
"""

import os
import json
import datetime
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AI_CSV = os.path.join(BASE_DIR, "emails.csv")
DATA_CSV = os.path.join(os.path.dirname(BASE_DIR), "data", "emails.csv")
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "model_metadata.json")

VALID_CLASSES = {"legitimate", "spam", "phishing", "suspicious"}


def load_and_validate_data():
    """Loads dataset from CSV files, validates schema, and deduplicates to prevent test leakage."""
    dfs = []
    if os.path.exists(AI_CSV):
        dfs.append(pd.read_csv(AI_CSV))
    elif os.path.exists(DATA_CSV):
        dfs.append(pd.read_csv(DATA_CSV))

    if not dfs:
        raise FileNotFoundError(f"No dataset found at {AI_CSV} or {DATA_CSV}.")

    data = pd.concat(dfs, ignore_index=True)

    # Validate schema
    if "text" not in data.columns or "label" not in data.columns:
        raise ValueError(f"Dataset must contain 'text' and 'label' columns. Found: {list(data.columns)}")

    data = data.dropna(subset=["text", "label"])
    data["text"] = data["text"].astype(str).str.strip()
    data["label"] = data["label"].astype(str).str.strip().str.lower()

    # Filter invalid labels
    invalid_labels = set(data["label"]) - VALID_CLASSES
    if invalid_labels:
        print(f"Warning: Found invalid labels {invalid_labels}. Filtering them out.")
        data = data[data["label"].isin(VALID_CLASSES)]

    # Prevent near-duplicate leakage
    data["normalized_text"] = data["text"].str.lower().str.replace(r'\s+', ' ', regex=True).str.strip()
    data = data.drop_duplicates(subset=["normalized_text"]).reset_index(drop=True)

    print(f"Loaded {len(data)} unique verified records.")
    print("Class breakdown:\n", data["label"].value_counts().to_string())

    return data


def train_and_evaluate():
    data = load_and_validate_data()

    X = data["text"]
    y = data["label"]

    # Stratified train/test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # High-accuracy TF-IDF + Calibrated Logistic Regression pipeline
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            lowercase=True,
            strip_accents="unicode",
            min_df=1
        )),
        ("classifier", LogisticRegression(
            C=2.5,
            class_weight="balanced",
            max_iter=1000,
            random_state=42
        ))
    ])

    # Cross-validation score on training set
    cv = StratifiedKFold(n_splits=4, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv, scoring="f1_macro")
    print(f"\nStratified 4-Fold Cross-Validation Macro-F1: {np.mean(cv_scores):.4f} (+/- {np.std(cv_scores):.4f})")

    # Fit final pipeline
    pipeline.fit(X_train, y_train)

    # Predict on unseen test set
    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)

    classes = list(pipeline.classes_)

    # Comprehensive evaluation metrics
    acc = accuracy_score(y_test, y_pred)
    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )
    precision_per_class, recall_per_class, f1_per_class, support_per_class = precision_recall_fscore_support(
        y_test, y_pred, labels=classes, zero_division=0
    )

    cm = confusion_matrix(y_test, y_pred, labels=classes)

    print("\n=======================================================")
    print("                MODEL EVALUATION REPORT                ")
    print("=======================================================")
    print(f"Overall Test Accuracy:    {acc * 100:.2f}%")
    print(f"Macro Average Precision:  {precision_macro * 100:.2f}%")
    print(f"Macro Average Recall:     {recall_macro * 100:.2f}%")
    print(f"Macro Average F1-Score:   {f1_macro * 100:.2f}%")
    print("\nDetailed Per-Class Performance:")
    print(classification_report(y_test, y_pred, labels=classes, zero_division=0))

    print("Confusion Matrix:")
    header = f"{'True \\ Pred':<15}" + "".join([f"{c:<14}" for c in classes])
    print(header)
    for idx, row in enumerate(cm):
        row_str = f"{classes[idx]:<15}" + "".join([f"{val:<14}" for val in row])
        print(row_str)

    # False Positive Rates per class
    # FPR_c = FP_c / (FP_c + TN_c)
    fpr_dict = {}
    print("\nFalse Positive Rate (FPR) Per Class:")
    for idx, c in enumerate(classes):
        tp = cm[idx, idx]
        fn = np.sum(cm[idx, :]) - tp
        fp = np.sum(cm[:, idx]) - tp
        tn = np.sum(cm) - (tp + fp + fn)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fpr_dict[c] = round(fpr, 4)
        print(f"  - {c.upper():<12} FPR: {fpr * 100:.2f}% (FP: {fp}, TN: {tn})")

    # Specific Legitimate Message False Positive Check
    # (Legitimate message mistakenly classified as Spam, Phishing, or Suspicious)
    legit_idx = classes.index("legitimate") if "legitimate" in classes else -1
    if legit_idx != -1:
        legit_total = np.sum(cm[legit_idx, :])
        legit_correct = cm[legit_idx, legit_idx]
        legit_fp = legit_total - legit_correct
        legit_error_rate = (legit_fp / legit_total) * 100 if legit_total > 0 else 0
        print(f"\n--> Legitimate Message False Positive Rate: {legit_error_rate:.2f}% ({legit_fp}/{legit_total} legitimate emails misclassified)")

    # Save model and metadata
    joblib.dump(pipeline, MODEL_PATH)
    print(f"\n[OK] Trained model successfully saved to: {MODEL_PATH}")

    metadata = {
        "classes": classes,
        "metrics": {
            "accuracy": round(acc, 4),
            "macro_precision": round(precision_macro, 4),
            "macro_recall": round(recall_macro, 4),
            "macro_f1": round(f1_macro, 4),
            "per_class": {
                c: {
                    "precision": round(precision_per_class[i], 4),
                    "recall": round(recall_per_class[i], 4),
                    "f1": round(f1_per_class[i], 4),
                    "support": int(support_per_class[i]),
                    "fpr": fpr_dict[c]
                }
                for i, c in enumerate(classes)
            }
        },
        "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_records": len(data)
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[OK] Model metadata saved to: {METADATA_PATH}")

    # Verification on realistic positive and negative test cases
    test_suite = [
        ("Your Unstop application for Software Engineering Intern has been submitted successfully.", "legitimate"),
        ("Unstop Alert: Login to your dashboard and complete your Round 2 assessment.", "legitimate"),
        ("Your college semester exam timetable is ready to view in the student portal.", "legitimate"),
        ("OTP for Email Verification is 492019. Valid for 10 minutes.", "legitimate"),
        ("URGENT! Your bank account will be blocked today. Verify your password immediately.", "phishing"),
        ("Security Alert: Your Google Account will be deleted in 24 hours. Sign in at http://fake-login.xyz", "phishing"),
        ("Congratulations! You won 50,000 GBP in the international lottery. Pay fee to claim.", "phishing"),
        ("Huge clearance sale! Up to 80% discount on designer shoes and watches.", "spam"),
        ("Urgent inquiry regarding contract agreement. Please contact me at private phone number.", "suspicious")
    ]

    print("\n--- Model Verification on Realistic Test Cases ---")
    for text, expected in test_suite:
        pred = pipeline.predict([text])[0]
        prob = pipeline.predict_proba([text])[0]
        confidence = max(prob) * 100
        match_icon = "[PASS]" if pred == expected else "[FAIL]"
        print(f"{match_icon} Expected: {expected.upper():<11} | Pred: {pred.upper():<11} ({confidence:.1f}%) | '{text[:60]}...'")

    return pipeline, metadata


if __name__ == "__main__":
    train_and_evaluate()
