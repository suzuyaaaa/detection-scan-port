import joblib
import pandas as pd

model = joblib.load("ml/model.pkl")
encoders = joblib.load("ml/encoders.pkl")


def preprocess(features: dict):
    df = pd.DataFrame([features])

    for col in ["proto", "service", "state"]:
        if col in df.columns:
            df[col] = encoders[col].transform(df[col])

    return df


def predict(features: dict):
    df = preprocess(features)

    pred = model.predict(df)[0]

    # si ton modèle supporte probas
    try:
        risk = model.predict_proba(df)[0][1]
    except:
        risk = 0.0

    return {
        "prediction": int(pred),
        "risk": float(risk)
    }
