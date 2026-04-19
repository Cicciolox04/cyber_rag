from langchain_ollama import OllamaEmbeddings
from langchain_chroma import Chroma

embeddings = OllamaEmbeddings(model="mistral", base_url="http://10.0.2.2:11434")
db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)

# Proviamo a cercare una tecnica specifica
risultati = db.similarity_search("Cifratura dei file per richiesta riscatto", k=1)

if risultati:
    print("Database pronto! Ecco un esempio di dato estratto:")
    print(f"Nome Tecnica: {risultati[0].metadata.get('name')}")
    print(f"Fasi Kill Chain: {risultati[0].metadata.get('phases')}")
else:
    print("Il database sembra vuoto. Riprova l'ingestione.")