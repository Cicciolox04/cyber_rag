from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")
db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)

def test_query(query_text):
    print(f"\n🔍 Query: '{query_text}'")
    print("-" * 50)
    risultati = db.similarity_search(query_text, k=2)
    
    for i, res in enumerate(risultati, 1):
        tipo = res.metadata.get('type', 'Unknown')
        idx = res.metadata.get('id', 'N/A')
        nome = res.metadata.get('name', 'N/A')
        
        icona = "🛡️ [CWE]" if tipo == "vulnerability" else "⚔️ [MITRE]"
        print(f"{i}. {icona} {idx} - {nome}")
    print("-" * 50)

# --- PROVA QUESTE TRE ---
# 1. Test puramente tecnico (CWE)
test_query("Buffer overflow in stringhe C")

# 2. Test puramente tattico (MITRE)
test_query("Persistenza tramite chiavi di registro")

# 3. Test "ponte" (Vediamo cosa attira di più)
test_query("Sfruttamento di credenziali deboli")