
import numpy as np
import joblib

# Load your existing trained 10-feature model
model = joblib.load("models/random_forest_10_features.pkl")

# Features MUST be in this exact order:
FEATURES_10 = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token",
    "SSLfinal_State",
    "port",
]

# CHANGE THESE VALUES to test your own vector
test_vector = [1, 1, 1, 1, 1, 1, 1, 1, -1, -1]

# Validate and run inference
assert len(test_vector) == len(FEATURES_10), "Expected 10 features"

sample = np.array([test_vector], dtype=int)

predicted_class = int(model.predict(sample)[0])
probabilities = model.predict_proba(sample)[0]

# Confirm probability order using the model's actual classes
print("Model classes:", model.classes_)

for class_label, probability in zip(model.classes_, probabilities):
    meaning = "PHISHING" if class_label == -1 else (
        "LEGITIMATE" if class_label == 1 else "UNKNOWN"
    )
    print(f"Class {class_label} ({meaning}): {probability:.4%}")

classification = {
    -1: "PHISHING",
    1: "LEGITIMATE",
}.get(predicted_class, "UNKNOWN")

phishing_index = list(model.classes_).index(-1)
phishing_probability = float(probabilities[phishing_index])

print("\n--- PREDICTION ---")
print("Feature vector:", test_vector)
print("Predicted class:", predicted_class)
print("Classification:", classification)
print(f"Phishing probability: {phishing_probability:.4%}")
