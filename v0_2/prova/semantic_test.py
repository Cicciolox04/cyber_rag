from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE (Allineata ai tuoi script di ingestion) ---
DB_DIR = '../chroma_db'
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")

# Caricamento del database esistente
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

def run_semantic_test(query, k=3):
    print(f"\n" + "="*50)
    print(f"🔍 QUERY DELL'ESPERTO: '{query}'")
    print("="*50)
    
    # Esecuzione della ricerca
    results = vector_db.similarity_search(query, k=k)
    
    if not results:
        print("❌ Nessun risultato trovato nel database.")
        return

    for i, doc in enumerate(results):
        m = doc.metadata
        source_type = m.get('type', 'N/A').upper()
        ext_id = m.get('id', 'N/A')
        name = m.get('name', 'N/A')
        
        print(f"\n[{i+1}] RISULTATO TROVATO:")
        print(f"   📌 FONTE: {source_type}")
        print(f"   🆔 ID: {ext_id}")
        print(f"   🏷️ NOME: {name}")
        print(f"   📝 ESTRATTO: {doc.page_content[:200]}...")
        print("-" * 30)

# --- ESECUZIONE TEST ---
# Test 1: Vediamo se riconosce una vulnerabilità software (CWE)
run_semantic_test("The application doesn't sanitize user input before sending it to a SQL query")

# Test 2: Vediamo se riconosce una tecnica di attacco (MITRE)
run_semantic_test("Attacker tries to move laterally using Remote Desktop Protocol")

# Test 3: Un caso misto (Pattern Cyber)
run_semantic_test("Exploiting a memory corruption to execute arbitrary code")