import pandas as pd
import os
from tqdm import tqdm
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE ---
CSV_FILE = '../data/cwe_list.csv'
DB_DIR = '../chroma_db'
BATCH_SIZE = 50

def find_header_row(file_path):
    """Cerca la riga del file che contiene l'intestazione corretta."""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if 'CWE-ID' in line and 'Name' in line:
                return i
    return 0

# 1. Caricamento dati
print("📊 Analisi file CWE...")
header_idx = find_header_row(CSV_FILE)
print(f"📍 Header trovato alla riga: {header_idx}")

# Carichiamo il CSV
df = pd.read_csv(CSV_FILE, low_memory=False, skiprows=header_idx)

# Pulizia nomi colonne
df.columns = [c.strip() for c in df.columns]

documents = []
print("🛠️ Elaborazione documenti con mappatura corretta...")

for index, row in df.iterrows():
    # --- FIX MAPPATURA ---
    # Poiché Pandas spesso usa la prima colonna (l'ID) come indice del DataFrame:
    cwe_raw_id = str(index).strip() 
    
    # Nel tuo CSV, la colonna 'CWE-ID' contiene effettivamente il Nome della vulnerabilità
    name = str(row.get('CWE-ID', '')).strip()
    
    # Se il nome estratto è un'astrazione (Base, Class, Variant), proviamo la colonna 'Name'
    if name.lower() in ['base', 'variant', 'class', 'nan']:
        name = str(row.get('Name', 'Unknown Weakness')).strip()

    description = str(row.get('Description', '')).strip()
    
    # Filtri di sicurezza per evitare righe sporche
    if not cwe_raw_id or cwe_raw_id.lower() in ['nan', 'cwe-id']:
        continue
    if not description or description.lower() == 'nan':
        continue

    # Formattazione ID (es. 120 -> CWE-120)
    cwe_id = f"CWE-{cwe_raw_id}" if "CWE" not in cwe_raw_id.upper() else cwe_raw_id

    # Costruiamo il contenuto per l'embedding
    content = f"ID: {cwe_id}\nVulnerability: {name}\nDescription: {description}"
    
    doc = Document(
        page_content=content, 
        metadata={
            "id": cwe_id, 
            "type": "vulnerability", 
            "name": name
        }
    )
    documents.append(doc)

if len(documents) == 0:
    print("❌ Errore: Non ho trovato dati validi. Controlla la mappatura delle colonne.")
else:
    print(f"✅ Preparate {len(documents)} vulnerabilità CWE con ID e Nomi corretti.")

    # 2. Configurazione Embeddings
    embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")

    # 3. Aggiornamento ChromaDB (Aggiunta al DB esistente)
    vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

    print(f"🚀 Inserimento in corso...")
    for i in tqdm(range(0, len(documents), BATCH_SIZE), desc="Indicizzazione CWE"):
        batch = documents[i : i + BATCH_SIZE]
        vector_db.add_documents(batch)

    print(f"\n✨ Database aggiornato correttamente! Ora puoi lanciare check_db.py")