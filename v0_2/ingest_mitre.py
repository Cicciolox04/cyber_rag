import json
import os
from tqdm import tqdm # Importiamo la barra di progresso
from langchain_classic.docstore.document import Document
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE ---
JSON_FILE = 'enterprise-attack.json'
DB_DIR = './chroma_db'
BATCH_SIZE = 50 # Numero di documenti caricati per ogni step della barra

# 1. Caricamento e Parsing del JSON
print("🔍 Analisi del file MITRE ATT&CK...")
with open(JSON_FILE, 'r') as f:
    mitre_data = json.load(f)

documents = []
for obj in mitre_data['objects']:
    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
        name = obj.get('name')
        desc = obj.get('description', 'Nessuna descrizione disponibile')
        phases = [p['phase_name'] for p in obj.get('kill_chain_phases', [])]
        
        content = f"Technique: {name}\nPhases: {', '.join(phases)}\nDescription: {desc}"
        doc = Document(page_content=content, metadata={"name": name, "phases": str(phases)})
        documents.append(doc)

print(f"✅ Trovate {len(documents)} tecniche valide.")

# 2. Configurazione Embeddings
embeddings = OllamaEmbeddings(model="mistral", base_url="http://10.0.2.2:11434")

# 3. Creazione ChromaDB e Caricamento a blocchi con TQDM
print(f"🚀 Inizio caricamento su ChromaDB (Batch size: {BATCH_SIZE})...")

# Inizializziamo il database vuoto
vector_db = Chroma(
    persist_directory=DB_DIR, 
    embedding_function=embeddings
)

# Dividiamo la lista dei documenti in blocchi e carichiamo con barra di progresso
for i in tqdm(range(0, len(documents), BATCH_SIZE), desc="Indicizzazione pattern"):
    batch = documents[i : i + BATCH_SIZE]
    vector_db.add_documents(batch)

print(f"\n✨ Operazione completata! Database salvato in: {DB_DIR}")