from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings

# --- CONFIGURAZIONE ---
DB_DIR = '../chroma_db'
embeddings = OllamaEmbeddings(model="bge-m3", base_url="http://10.0.2.2:11434")

# Inizializziamo il database
vector_db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)

def test_kill_chain_filter(target_phase):
    print(f"\n" + "="*50)
    print(f"🛡️ FILTRO KILL CHAIN: '{target_phase}'")
    print("="*50)
    
    # 1. Recuperiamo i documenti che parlano di comunicazione esterna
    # Cerchiamo un numero maggiore di risultati (k=20) per poi filtrarli manualmente
    query = "Communication with external servers and remote command execution"
    results = vector_db.similarity_search(
        query, 
        k=20, 
        filter={"type": "mitre_technique"} # Filtriamo subito per assicurarci siano tecniche MITRE
    )
    
    found_count = 0
    for doc in results:
        # Recuperiamo la stringa delle fasi dai metadati
        phases_metadata = doc.metadata.get('phases', '').lower()
        
        # Verifichiamo se la fase cercata è contenuta nella stringa
        if target_phase.lower() in phases_metadata:
            found_count += 1
            print(f"✅ [{found_count}] {doc.metadata.get('id')} - {doc.metadata.get('name')}")
            # Opzionale: decommenta la riga sotto per vedere il contenuto
            # print(f"   📝 {doc.page_content[:100]}...")
            
    if found_count == 0:
        print(f"⚠️ Nessuna tecnica trovata per la fase '{target_phase}' nei primi 20 risultati.")
    else:
        print(f"\n✨ Trovati {found_count} pattern pertinenti per la fase specificata.")

# --- ESECUZIONE ---
# Proviamo con la fase di Command and Control
test_kill_chain_filter("command-and-control")

# Facciamo un secondo test per la fase di Discovery (Ricognizione interna)
test_kill_chain_filter("discovery")