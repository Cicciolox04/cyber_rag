from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

embeddings = OllamaEmbeddings(model="mistral", base_url="http://10.0.2.2:11434")
db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)

# Cerchiamo specificamente una debolezza software
query = "funzione strcpy senza controllo del limite"
risultati = db.similarity_search(query, k=3)

for r in risultati:
    print(f"Trovato: {r.metadata.get('id')} - {r.metadata.get('name')}")