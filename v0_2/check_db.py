from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# Configurazione Embeddings e Database
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")
db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)

# Nuova tecnica da analizzare: Esfiltrazione dati (molto comune nei report di attacco)
query = "Buffer overflow causato da stringhe troppo lunghe"
risultati = db.similarity_search(query, k=1)

if risultati:
    res = risultati[0]
    print(f"🔍 Risultato della ricerca per: '{query}'")
    print("-" * 40)
    # Ora recuperiamo l'ID che abbiamo aggiunto nell'ingestione
    print(f"ID Tecnica: {res.metadata.get('id')}") 
    print(f"Nome Tecnica: {res.metadata.get('name')}")
    print(f"Fasi Kill Chain: {res.metadata.get('phases')}")
else:
    print("Il database sembra vuoto. Riprova l'ingestione.")