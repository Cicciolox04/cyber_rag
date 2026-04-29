import json
import os
from tqdm import tqdm
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE ---
JSON_FILE = '../data/capec.json'
DB_DIR = '../chroma_db'
BATCH_SIZE = 50 

print("🔍 Analisi del file CAPEC...")
with open(JSON_FILE, 'r') as f:
    capec_data = json.load(f)

documents = []
for obj in capec_data['objects']:
    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
        name = obj.get('name')
        desc = obj.get('description', 'Nessuna descrizione disponibile')
        
        capec_id = "N/A"
        related_cwes = []
        
        if obj.get('external_references'):
            for ref in obj['external_references']:
                source = ref.get('source_name', '').lower()
                ext_id = ref.get('external_id')
                if source == 'capec': capec_id = ext_id
                elif source == 'cwe': related_cwes.append(ext_id)
        
        content = f"ID: {capec_id}\nAttack Pattern: {name}\nRelated CWEs: {', '.join(related_cwes)}\nDescription: {desc}"
        
        doc = Document(
            page_content=content, 
            metadata={"id": capec_id, "name": name, "type": "capec_pattern"}
        )
        documents.append(doc)

print(f"🚀 Indicizzazione di {len(documents)} pattern CAPEC...")
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

for i in tqdm(range(0, len(documents), BATCH_SIZE), desc="Indicizzazione CAPEC"):
    batch = documents[i : i + BATCH_SIZE]
    vector_db.add_documents(batch)

print(f"\n✨ CAPEC integrato correttamente!")