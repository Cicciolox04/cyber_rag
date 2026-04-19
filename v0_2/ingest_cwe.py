import pandas as pd
from tqdm import tqdm
from langchain_classic.docstore.document import Document
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE ---
CSV_FILE = 'cwe_list.csv'
DB_DIR = './chroma_db'
BATCH_SIZE = 50

# 1. Caricamento dati (saltando le prime righe di intestazione del file MITRE)
print("📊 Caricamento dataset CWE...")
df = pd.read_csv(CSV_FILE, low_memory=False)

documents = []
# Iteriamo sulle righe del CSV (CWE-ID, Name, Description, etc.)
for index, row in df.iterrows():
    cwe_id = row.get('CWE-ID')
    name = row.get('Name')
    description = row.get('Description')
    
    if pd.isna(cwe_id) or pd.isna(description):
        continue

    content = f"CWE-{cwe_id}: {name}\nDescription: {description}"
    doc = Document(
        page_content=content, 
        metadata={"id": f"CWE-{cwe_id}", "type": "vulnerability", "name": name}
    )
    documents.append(doc)

print(f"✅ Preparate {len(documents)} vulnerabilità CWE.")

# 2. Configurazione Embeddings
embeddings = OllamaEmbeddings(model="mistral", base_url="http://10.0.2.2:11434")

# 3. Aggiornamento ChromaDB
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

print(f"🚀 Inserimento CWE nel database esistente...")
for i in tqdm(range(0, len(documents), BATCH_SIZE), desc="Indicizzazione CWE"):
    batch = documents[i : i + BATCH_SIZE]
    vector_db.add_documents(batch)

print(f"\n✨ Cultura tecnica aggiornata! Il database ora conosce anche le falle software.")