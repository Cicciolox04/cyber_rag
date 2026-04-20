import pandas as pd

df = pd.read_csv('../data/cwe_list.csv', low_memory=False, nrows=5)
print("🔍 Ecco le colonne che ho trovato:")
print(df.columns.tolist())
print("\n🔍 Ecco le prime due righe:")
print(df.head(2))