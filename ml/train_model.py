import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# Charger dataset nettoyé
df = pd.read_csv("dataset/UNSW_NB15_cleaned.csv")

# Créer la cible : 1 si Reconnaissance, sinon 0
df["scan_label"] = df["attack_cat"].apply(
    lambda x: 1 if x == "Reconnaissance" else 0
)

# Supprimer colonnes inutiles
X = df.drop(columns=["attack_cat", "label", "scan_label"])
y = df["scan_label"]

# Encoder les colonnes texte
categorical_columns = ["proto", "service", "state"]

encoders = {}

for col in categorical_columns:
    le = LabelEncoder()
    X[col] = le.fit_transform(X[col].astype(str))
    encoders[col] = le

# Séparer train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Créer modèle
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Entraîner
model.fit(X_train, y_train)

# Tester
y_pred = model.predict(X_test)

print("Accuracy :", accuracy_score(y_test, y_pred))
print("\nConfusion Matrix :")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report :")
print(classification_report(y_test, y_pred))

# Sauvegarder modèle
joblib.dump(model, "ml/model.pkl")
joblib.dump(encoders, "ml/encoders.pkl")

print("\nModèle sauvegardé dans ml/model.pkl")
