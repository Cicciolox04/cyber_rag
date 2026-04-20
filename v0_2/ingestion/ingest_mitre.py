import json
import os
import shutil
from tqdm import tqdm
from langchain_core.documents import Document
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE ---
JSON_FILE = '../data/enterprise-attack.json'
DB_DIR = '../chroma_db'
BATCH_SIZE = 50 

# 1. Caricamento e Parsing del JSON
print("🔍 Analisi del file MITRE ATT&CK...")
with open(JSON_FILE, 'r') as f:
    mitre_data = json.load(f)

documents = []
for obj in mitre_data['objects']:
    # Filtriamo solo i pattern di attacco non deprecati
    if obj.get('type') == 'attack-pattern' and not obj.get('x_mitre_deprecated'):
        name = obj.get('name')
        desc = obj.get('description', 'Nessuna descrizione disponibile')
        phases = [p['phase_name'] for p in obj.get('kill_chain_phases', [])]
        
        # --- ESTRAZIONE ID MITRE (Txxxx) ---
        external_id = "N/A"
        if obj.get('external_references'):
            for ref in obj['external_references']:
                if ref.get('source_name') == 'mitre-attack':
                    external_id = ref.get('external_id')
                    break
        
        # Inseriamo l'ID nel contenuto per migliorare la ricerca semantica
        content = f"ID: {external_id}\nTechnique: {name}\nPhases: {', '.join(phases)}\nDescription: {desc}"
        
        # Salviamo l'ID nei metadati per renderlo recuperabile dallo script di check
        doc = Document(
            page_content=content, 
            metadata={
                "id": external_id, 
                "name": name, 
                "phases": str(phases),
                "type": "mitre_technique"
            }
        )
        documents.append(doc)

print(f"✅ Trovate {len(documents)} tecniche valide con ID mappati.")

# 2. Reset del Database (Consigliato se cambi modello o struttura)
if os.path.exists(DB_DIR):
    print(f"🧹 Pulizia database esistente in {DB_DIR}...")
    shutil.rmtree(DB_DIR)

# 3. Configurazione Embeddings (bge-m3 per precisione multilingua)
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")

# 4. Caricamento su ChromaDB
print(f"🚀 Inizio caricamento su ChromaDB...")
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

for i in tqdm(range(0, len(documents), BATCH_SIZE), desc="Indicizzazione pattern"):
    batch = documents[i : i + BATCH_SIZE]
    vector_db.add_documents(batch)

print(f"\n✨ Operazione completata! Ora il database contiene gli ID delle tecniche.")