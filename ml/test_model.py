import joblib
import pandas as pd

# Charger modèle
model = joblib.load("ml/model.pkl")
encoders = joblib.load("ml/encoders.pkl")

# Exemple de données simulées (très important)
data = {
    "dur": [0.1],
    "proto": ["tcp"],
    "service": ["http"],
    "state": ["FIN"],
    "spkts": [10],
    "dpkts": [8],
    "sbytes": [500],
    "dbytes": [300],
    "rate": [100],
    "sttl": [64],
    "dttl": [64],
    "sload": [200],
    "dload": [150],
    "sloss": [0],
    "dloss": [0],
    "sinpkt": [0.01],
    "dinpkt": [0.01],
    "sjit": [0],
    "djit": [0],
    "swin": [255],
    "stcpb": [0],
    "dtcpb": [0],
    "dwin": [255],
    "tcprtt": [0.1],
    "synack": [0.05],
    "ackdat": [0.05],
    "smean": [50],
    "dmean": [40],
    "trans_depth": [0],
    "response_body_len": [0],
    "ct_srv_src": [2],
    "ct_state_ttl": [1],
    "ct_dst_ltm": [1],
    "ct_src_dport_ltm": [1],
    "ct_dst_sport_ltm": [1],
    "ct_dst_src_ltm": [1],
    "is_ftp_login": [0],
    "ct_ftp_cmd": [0],
    "ct_flw_http_mthd": [0],
    "ct_src_ltm": [1],
    "ct_srv_dst": [1],
    "is_sm_ips_ports": [0]
}

df = pd.DataFrame(data)

# Encoder
for col in ["proto", "service", "state"]:
    df[col] = encoders[col].transform(df[col])

# Prédiction
prediction = model.predict(df)

if prediction[0] == 1:
    print("⚠️ Scan détecté")
else:
    print("✅ Trafic normal")
