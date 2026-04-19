from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# Configurazione corretta per il tuo NAT
OLLAMA_URL = "http://10.0.2.2:11434"
PERSIST_DIR = "./exploit_db_weights"

embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=OLLAMA_URL)
vectorstore = Chroma(persist_directory=PERSIST_DIR, embedding_function=embeddings)

# Proviamo una query specifica
query = "ASUS ASMB8 iKVM Remote Code Execution 2025"
print(f"[*] Ricerca semantica per: {query}")

docs = vectorstore.similarity_search(query, k=3)

print("\n--- RISULTATI RECUPERATI DAL DB ---")
for i, d in enumerate(docs):
    print(f"\n[Documento {i+1}]")
    print(f"ID: {d.metadata.get('exploit_id')}")
    print(f"Contenuto: {d.page_content[:200]}...")