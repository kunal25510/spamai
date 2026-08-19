import os
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, classification_report

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AI_CSV = os.path.join(BASE_DIR, "emails.csv")
DATA_CSV = os.path.join(os.path.dirname(BASE_DIR), "data", "emails.csv")
MODEL_PATH = os.path.join(BASE_DIR, "phishing_model.pkl")

# Load and combine datasets
dfs = []
if os.path.exists(DATA_CSV):
    dfs.append(pd.read_csv(DATA_CSV))
if os.path.exists(AI_CSV):
    dfs.append(pd.read_csv(AI_CSV))

data = pd.concat(dfs, ignore_index=True) if dfs else pd.read_csv(DATA_CSV)
data = data.dropna(subset=["text", "label"])
data["text"] = data["text"].astype(str).str.strip()
data["label"] = data["label"].astype(str).str.strip().str.lower()
data = data.drop_duplicates(subset=["text", "label"])

X = data["text"]
y = data["label"]

# Train / Test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Pipeline with optimized vectorizer and classifier
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        lowercase=True,
        strip_accents="unicode",
        min_df=1
    )),
    ("classifier", LogisticRegression(C=1.5, max_iter=1000))
])

# Train model
model.fit(X_train, y_train)

# Save trained model
joblib.dump(model, MODEL_PATH)
print(f"Model saved successfully to {MODEL_PATH}")

# Evaluation
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"\nModel Accuracy on Test Split: {accuracy * 100:.2f}%")

# Test verification set of legitimate and phishing emails
test_emails = [
    "You shared some Google Account data with Kaggle. You're receiving this email because you used Sign in with Google to sign in to Kaggle.",
    "IPPB Adds convenience to your Post Office Savings Account. Customer, Experience the trust of India Post.",
    "Certificate Expiring in 7 Days: orbit-strategies.co. This is to notify you that your certificate with common name orbit-strategies.co will expire soon.",
    "OTP for Email Verification - MahaSarathi. Your OTP is 654321.",
    "URGENT! Your bank account will be blocked today. Verify your password immediately.",
    "Congratulations! You won 50000 rupees. Click here to claim your prize."
]

print("\n--- Legitimate vs Phishing Probabilities ---")
for email in test_emails:
    prediction = model.predict([email])[0]
    probabilities = model.predict_proba([email])[0]
    classes = list(model.classes_)
    phish_idx = classes.index("phishing") if "phishing" in classes else 0
    phish_prob = probabilities[phish_idx] * 100
    print(f"Email snippet: '{email[:70]}...'")
    print(f"  Prediction: {prediction.upper()} | Phishing Probability: {phish_prob:.2f}%\n")

