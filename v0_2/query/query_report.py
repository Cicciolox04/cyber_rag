from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama

# --- CONFIGURAZIONE ---
DB_DIR = "../chroma_db"
URL_OLLAMA = "http://10.0.2.2:11434"

def test_query(question):
    print(f"\n❓ Domanda: {question}")
    print("⏳ Ricerca nel report in corso...")

    # 1. Inizializzazione
    embeddings = OllamaEmbeddings(model="bge-m3", base_url=URL_OLLAMA)
    db = Chroma(persist_directory=DB_DIR, embedding_function=embeddings)
    llm = ChatOllama(model="mistral", base_url=URL_OLLAMA, temperature=0.1)

    # 2. Retrieval: cerchiamo solo tra i report (usando il filtro sui metadati)
    # k=5 per prendere abbastanza contesto da pagine diverse
    docs = db.similarity_search(question, k=5, filter={"type": "threat-report"})

    if not docs:
        print("❌ Nessun dato trovato nel database. Hai eseguito l'ingestione?")
        return

    # Uniamo i frammenti trovati
    context = "\n---\n".join([d.page_content for d in docs])

    # 3. Prompt per l'analisi del report
    prompt = f"""
    Sei un analista di Cyber Threat Intelligence. Utilizza esclusivamente i seguenti estratti del report Mandiant M-Trends 2025 per rispondere alla domanda.
    
    CONTESTO ESTRATTO DAL REPORT:
    {context}
    
    DOMANDA: {question}
    
    ISTRUZIONI:
    - Se le informazioni non sono presenti nel contesto, dichiara di non poter rispondere basandoti solo su questo report.
    - Cita dati specifici o percentuali se presenti.
    - Mantieni un tono professionale.
    """

    # 4. Generazione risposta
    print("🤖 Mistral sta elaborando i dati...\n")
    response = llm.invoke(prompt)
    print("--- RISPOSTA DELL'AGENT ---")
    print(response.content)
    print("-" * 30)

if __name__ == "__main__":
    # Test 1: Ransomware
    test_query("Quali sono i principali trend del Ransomware identificati nel report?")