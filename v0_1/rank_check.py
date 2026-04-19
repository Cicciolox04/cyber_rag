from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url="http://10.0.2.2:11434")
vectorstore = Chroma(persist_directory="./exploit_db_weights", embedding_function=embeddings)

query = "ASUS ASMB8 iKVM 1.14.51" # Usiamo i termini esatti del documento

# Chiediamo i primi 100 risultati invece di 5
docs_with_scores = vectorstore.similarity_search_with_score(query, k=100)

print(f"[*] Analisi dei primi 100 risultati per: '{query}'")
found = False
for rank, (doc, score) in enumerate(docs_with_scores, 1):
    eid = doc.metadata.get('exploit_id')
    if eid == "52244":
        print(f"\n🎯 TROVATO! Posizione: {rank} | Score: {score}")
        print(f"Contenuto: {doc.page_content[:100]}...")
        found = True
        break

if not found:
    print("\n❌ Nemmeno nei primi 100. C'è un problema di allineamento dei vettori.")