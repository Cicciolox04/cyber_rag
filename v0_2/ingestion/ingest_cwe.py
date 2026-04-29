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
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if 'CWE-ID' in line and 'Name' in line:
                return i
    return 0

print("📊 Analisi file CWE...")
header_idx = find_header_row(CSV_FILE)

df = pd.read_csv(CSV_FILE, low_memory=False, skiprows=header_idx)
df.columns = [c.strip() for c in df.columns]

documents = []
for index, row in df.iterrows():
    cwe_raw_id = str(index).strip() 
    name = str(row.get('CWE-ID', '')).strip()
    
    if name.lower() in ['base', 'variant', 'class', 'nan']:
        name = str(row.get('Name', 'Unknown Weakness')).strip()

    description = str(row.get('Description', '')).strip()
    
    if not cwe_raw_id or cwe_raw_id.lower() in ['nan', 'cwe-id'] or not description or description.lower() == 'nan':
        continue

    cwe_id = f"CWE-{cwe_raw_id}" if "CWE" not in cwe_raw_id.upper() else cwe_raw_id
    content = f"ID: {cwe_id}\nVulnerability: {name}\nDescription: {description}"
    
    doc = Document(
        page_content=content, 
        metadata={
            "id": cwe_id, 
            "type": "cwe_weakness", # FIX: Cambiato da 'vulnerability' per ricerca semantica
            "name": name
        }
    )
    documents.append(doc)

print(f"✅ Preparate {len(documents)} vulnerabilità CWE.")

embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

print(f"🚀 Inserimento in corso...")
for i in tqdm(range(0, len(documents), BATCH_SIZE), desc="Indicizzazione CWE"):
    batch = documents[i : i + BATCH_SIZE]
    vector_db.add_documents(batch)

print(f"\n✨ CWE integrato correttamente!")