import pandas as pd

df = pd.read_csv("/usr/share/exploitdb/files_exploits.csv", low_memory=False)
df['date_published'] = pd.to_datetime(df['date_published'], errors='coerce')
df = df.sort_values(by='date_published')
latest_2000 = df.tail(2000)

print(f"Data più vecchia nel RAG: {latest_2000['date_published'].min()}")
print(f"Data più recente nel RAG: {latest_2000['date_published'].max()}")

# Controlliamo se l'ID 52244 (ASUS) è nel gruppo
is_present = "52244" in latest_2000['id'].astype(str).values
print(f"L'exploit ASUS (52244) è nel range? {'✅ SÌ' if is_present else '❌ NO'}")