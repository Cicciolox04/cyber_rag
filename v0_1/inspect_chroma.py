from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# Configurazione (Assicurati che sia 10.0.2.2)
OLLAMA_URL = "http://10.0.2.2:11434"
PERSIST_DIR = "./exploit_db_weights"
EMBED_MODEL = "nomic-embed-text"

embeddings = OllamaEmbeddings(model=EMBED_MODEL, base_url=OLLAMA_URL)
vectorstore = Chroma(persist_directory=PERSIST_DIR, embedding_function=embeddings)

# 1. Quanti record ci sono davvero?
all_data = vectorstore.get()
ids_in_db = all_data['ids']
print(f"[?] Totale record in Chroma: {len(ids_in_db)}")

# 2. Vediamo i primi 3 ID per capire se sono quelli del 2025/26
print(f"[?] Esempio ID nel DB: {ids_in_db[:3]}")

# 3. Cerchiamo l'ID 52244 tramite metadati (FILTRO RIGIDO)
# Nota: assicurati che la chiave nel metadato sia quella usata nell'ingestore ('exploit_id')
res = vectorstore.get(where={"exploit_id": "52244"})

if res['ids']:
    print("\n✅ IL DATO ESISTE!")
    print(f"Contenuto salvato:\n{res['documents'][0]}")
    print(f"Metadati salvati:\n{res['metadatas'][0]}")
else:
    print("\n❌ IL DATO NON ESISTE nel database vettoriale.")
    if len(all_data['metadatas']) > 0:
        print(f"Esempio di metadati presenti: {all_data['metadatas'][0]}")