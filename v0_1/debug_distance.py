from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url="http://10.0.2.2:11434")
vectorstore = Chroma(persist_directory="./exploit_db_weights", embedding_function=embeddings)

query = "ASUS ASMB8 iKVM Remote Code Execution" # Ho tolto 2025 per evitare rumore
print(f"[*] Ricerca estesa per: {query}")

# Aumentiamo k a 20 e chiediamo i punteggi di distanza
docs_with_scores = vectorstore.similarity_search_with_score(query, k=20)

found = False
for i, (doc, score) in enumerate(docs_with_scores):
    eid = doc.metadata.get('exploit_id')
    if eid == "52244":
        print(f"\n✅ TROVATO! L'ID 52244 è alla posizione {i+1} con score {score}")
        found = True
        break

if not found:
    print("\n❌ L'ID 52244 non è nemmeno nei primi 20 risultati.")