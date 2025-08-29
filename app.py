from fastapi import FastAPI
from pydantic import BaseModel
import joblib

# Load model
model = joblib.load("Phishing_model.pkl")

# FastAPI app
app = FastAPI()

class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"message": "URLDetective API is running"}

@app.post("/predict-url")
def predict(data: URLRequest):
    prediction = model.predict([[len(data.url)]])
    return {"url": data.url, "prediction": int(prediction[0])}
