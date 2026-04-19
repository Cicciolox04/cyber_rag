from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma

# Configurazione
URL_OLLAMA = "http://10.0.2.2:11434"
embeddings = OllamaEmbeddings(model="mistral", base_url=URL_OLLAMA)
db = Chroma(persist_directory="./chroma_db", embedding_function=embeddings)
llm = ChatOllama(model="mistral", base_url=URL_OLLAMA, temperature=0.1) # Temperatura bassa = più precisione

def analyze_and_predict(input_data):
    # 1. RETRIEVAL: Trova i pattern più simili
    print(f"🔍 Analizzando l'input...")
    docs = db.similarity_search(input_data, k=3)
    
    context = ""
    for d in docs:
        context += f"\n---\nTecnica: {d.metadata['name']}\nFasi: {d.metadata['phases']}\nDescrizione: {d.page_content}\n"

    # 2. PROMPT ENGINEERING: Definiamo il ragionamento
    prompt = f"""
    Sei un esperto di Cyber Threat Intelligence. Analizza il seguente input sospetto:
    '{input_data}'

    Utilizza questi pattern reali dal MITRE ATT&CK come contesto:
    {context}

    Segui rigorosamente questo schema di risposta:
    1. IDENTIFICAZIONE: Quale tecnica MITRE è più probabile? In quale fase della Cyber Kill Chain siamo?
    2. RAGIONAMENTO: Perché questo input è pericoloso?
    3. PREDIZIONE: Data la fase attuale, quale sarà la PROSSIMA mossa logica dell'attaccante nella Cyber Kill Chain? 
    4. MITIGAZIONE: Cosa dovrebbe fare subito un sistemista per bloccare questa progressione?
    """

    print("🤖 Mistral sta elaborando la predizione...\n")
    response = llm.invoke(prompt)
    return response.content

# --- TEST REALE ---
test_input = "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..." 
# (Esempio di comando PowerShell codificato in Base64)

report = analyze_and_predict(test_input)
print(report)