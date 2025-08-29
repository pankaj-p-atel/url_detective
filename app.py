from fastapi import FastAPI
from pydantic import BaseModel
import joblib
from urllib.parse import urlparse
import re

# Load model
model = joblib.load("Phishing_model.pkl")

# FastAPI app
app = FastAPI()

class URLRequest(BaseModel):
    url: str

# -------- Feature Extraction -------- #
def extract_features(url: str):
    features = []
    # 1. Length of URL
    features.append(len(url))
    # 2. Number of dots
    features.append(url.count('.'))
    # 3. Presence of '@'
    features.append(1 if "@" in url else 0)
    # 4. Presence of '-'
    features.append(1 if "-" in url else 0)
    # 5. Count of slashes
    features.append(url.count('/'))
    # 6. Count of digits
    features.append(sum(c.isdigit() for c in url))
    # 7. Count of special chars
    features.append(len(re.findall(r'[^a-zA-Z0-9]', url)))
    # 8. Length of domain
    try:
        features.append(len(urlparse(url).netloc))
    except:
        features.append(0)
    # 9. Is HTTPS
    features.append(1 if url.startswith("https") else 0)
    # 10. Number of subdomains
    try:
        features.append(len(urlparse(url).netloc.split(".")) - 2)
    except:
        features.append(0)
    # 11. Count of '?'
    features.append(url.count('?'))
    # 12. Count of '='
    features.append(url.count('='))
    # 13. Count of '%'
    features.append(url.count('%'))
    # 14. Count of '.com'
    features.append(url.count('.com'))
    # 15. Count of 'https'
    features.append(url.count('https'))
    # 16. Length of path
    try:
        features.append(len(urlparse(url).path))
    except:
        features.append(0)
    # 17. Length of query
    try:
        features.append(len(urlparse(url).query))
    except:
        features.append(0)
    # 18. Digits in domain
    try:
        features.append(sum(c.isdigit() for c in urlparse(url).netloc))
    except:
        features.append(0)
    # 19. Has suspicious words
    suspicious_words = ["login", "update", "secure", "account", "banking"]
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)
    # 20. Count of '&'
    features.append(url.count('&'))
    # 21. Count of '#'
    features.append(url.count('#'))

    return features

# -------- Routes -------- #
@app.get("/")
def home():
    return {"message": "URLDetective API is running"}

@app.post("/predict-url")
def predict(data: URLRequest):
     # example feature extraction
    features = [len(data.url), data.url.count("."), data.url.count("/")]
    prediction = model.predict([features])[0]
    label = "phishing" if prediction == 1 else "legitimate"

    return {
        "url": data.url,
        "features_order": ["length", "dot_count", "slash_count"],
        "features": features,
        "prediction": int(prediction),
        "label": label
    }
    # features = extract_features(data.url)   # ✅ generate 21 features
    # prediction = model.predict([features])  # pass correct input
    # return {"url": data.url, "prediction": int(prediction[0])}
