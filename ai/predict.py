import os
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

# Load the trained model
if not os.path.exists(MODEL_PATH):
    print("Model file not found! Please run train_model.py first.")
    exit(1)

model = joblib.load(MODEL_PATH)

# Email to analyze
email = input("Enter email text: ")

if not email.strip():
    print("No text provided.")
    exit(0)

# Make prediction
prediction = model.predict([email])[0]

# Get confidence
probabilities = model.predict_proba([email])[0]
classes = list(model.classes_)
phish_idx = classes.index("phishing") if "phishing" in classes else 0
phish_prob = probabilities[phish_idx] * 100

print("\n--- Security Analysis ---")
print("Prediction:", prediction.upper())
print(f"Phishing Probability: {phish_prob:.2f}%")
print(f"Safe Probability: {(100 - phish_prob):.2f}%")