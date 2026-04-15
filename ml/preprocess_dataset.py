import pandas as pd

# 1️ Charger les datasets
train_path = "dataset/UNSW_NB15_training-set.csv"
test_path = "dataset/UNSW_NB15_testing-set.csv"

train_df = pd.read_csv(train_path)
test_df = pd.read_csv(test_path)

print("Datasets chargés")
print("Train shape :", train_df.shape)
print("Test shape :", test_df.shape)

# 2️ Fusionner train + test
df = pd.concat([train_df, test_df], ignore_index=True)

print("Dataset combiné :", df.shape)

# 3️ Supprimer colonnes inutiles
columns_to_drop = ["id"]  # ID inutile 
df.drop(columns=columns_to_drop, inplace=True, errors='ignore')

# 4️ Supprimer doublons
df = df.drop_duplicates()

# 5️ Gérer valeurs manquantes
df = df.dropna()

print("Après nettoyage :", df.shape)

# 6️ Vérifier les colonnes importantes
print("\nColonnes disponibles :")
print(df.columns)

# 7️ Vérifier les types d'attaques
if "attack_cat" in df.columns:
    print("\nTypes d'attaques :")
    print(df["attack_cat"].value_counts())
else:
    print(" Colonne attack_cat manquante")

# 8️ Sauvegarder dataset nettoyé
output_path = "dataset/UNSW_NB15_cleaned.csv"
df.to_csv(output_path, index=False)

print("\nDataset nettoyé sauvegardé !")
