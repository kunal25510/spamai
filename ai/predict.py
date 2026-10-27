"""
Sentinel Security Agent - CLI Classifier
Loads the 4-class model and displays detailed class probabilities.
"""

import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

if not os.path.exists(MODEL_PATH):
    print(f"Model file not found at {MODEL_PATH}! Please run train_model.py first.")
    exit(1)

model = joblib.load(MODEL_PATH)

def analyze_text(email_text):
    if not email_text.strip():
        print("No text provided.")
        return

    prediction = model.predict([email_text])[0]
    probabilities = model.predict_proba([email_text])[0]
    classes = list(model.classes_)

    print("\n--- Sentinel Security Analysis ---")
    print(f"Predicted Category: {prediction.upper()}")
    print("Class Probabilities:")
    for cls, prob in sorted(zip(classes, probabilities), key=lambda x: x[1], reverse=True):
        print(f"  - {cls.upper():<12}: {prob * 100:.2f}%")

if __name__ == "__main__":
    email = input("Enter email text: ")
    analyze_text(email)