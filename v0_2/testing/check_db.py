from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# Configurazione Embeddings e Database
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")
db = Chroma(persist_directory="../chroma_db", embedding_function=embeddings)

# Nuova tecnica da analizzare: Esfiltrazione dati (molto comune nei report di attacco)
query = "SQL Injection"
risultati = db.similarity_search(query, k=1)

# ... (parte iniziale dello script)

if risultati:
    res = risultati[0]
    tipo = res.metadata.get('type')
    
    print(f"🔍 Risultato della ricerca per: '{query}'")
    print("-" * 40)
    print(f"ID: {res.metadata.get('id')}")
    print(f"Nome: {res.metadata.get('name')}")

    # Gestione dinamica dell'output
    if tipo == "vulnerability":
        print("Fasi Kill Chain: N/A (Questa è una vulnerabilità software, non una fase d'attacco)")
    else:
        print(f"Fasi Kill Chain: {res.metadata.get('phases')}")
else:
    print("Il database sembra vuoto. Riprova l'ingestione.")