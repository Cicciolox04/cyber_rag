import json
import os
from tqdm import tqdm
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE ---
JSON_FILE = '../data/enterprise-attack.json'
DB_DIR = '../chroma_db'
BATCH_SIZE = 50 

print("🔍 Analisi del file MITRE ATT&CK...")
with open(JSON_FILE, 'r') as f:
    mitre_data = json.load(f)

documents = []
for obj in mitre_data['objects']:
    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
        name = obj.get('name')
        desc = obj.get('description', 'Nessuna descrizione disponibile')
        phases = [p['phase_name'] for p in obj.get('kill_chain_phases', [])]
        
        external_id = "N/A"
        if obj.get('external_references'):
            for ref in obj['external_references']:
                if ref.get('source_name') == 'mitre-attack':
                    external_id = ref.get('external_id')
                    break
        
        content = f"ID: {external_id}\nTechnique: {name}\nPhases: {', '.join(phases)}\nDescription: {desc}"
        
        doc = Document(
            page_content=content, 
            metadata={
                "id": external_id, 
                "name": name, 
                "type": "mitre_technique" # Coerente con il retriever
            }
        )
        documents.append(doc)

print(f"✅ Trovate {len(documents)} tecniche valide.")

# Embeddings (bge-m3)
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")

# Caricamento su ChromaDB (Additivo)
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

print(f"🚀 Inizio caricamento su ChromaDB...")
for i in tqdm(range(0, len(documents), BATCH_SIZE), desc="Indicizzazione MITRE"):
    batch = documents[i : i + BATCH_SIZE]
    vector_db.add_documents(batch)

print(f"\n✨ MITRE ATT&CK integrato correttamente!")