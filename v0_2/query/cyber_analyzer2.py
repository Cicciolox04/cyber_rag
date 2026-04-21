from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma

# Configurazione
URL_OLLAMA = "http://10.0.2.2:11434"
embeddings = OllamaEmbeddings(model="bge-m3", base_url=URL_OLLAMA)
db = Chroma(persist_directory="../chroma_db", embedding_function=embeddings)
llm = ChatOllama(model="mistral", base_url=URL_OLLAMA, temperature=0.1)

def analyze_multi_hypothesis(input_data):
    print(f"🔍 Analizzando l'input con approccio multi-ipotesi...")
    
    # Prendiamo i primi 5 risultati per avere una visione d'insieme
    docs = db.similarity_search(input_data, k=5)
    
    context_list = []
    for d in docs:
        item_id = d.metadata.get('id', 'N/A')
        name = d.metadata.get('name', 'N/A')
        source_type = d.metadata.get('type', 'Unknown')
        context_list.append(f"[{source_type.upper()}] ID: {item_id} | Nome: {name}\nDescrizione: {d.page_content}")

    context = "\n---\n".join(context_list)

    prompt = f"""
    Sei un esperto di Cyber Threat Intelligence. Analizza il seguente evento sospetto:
    '{input_data}'

    Dalla base di conoscenza (MITRE/CWE) sono emersi questi 5 candidati:
    {context}

    ISTRUZIONI:
    1. VALUTAZIONE: Valuta i candidati e identifica i 3 più probabili, spiegando brevemente perché si adattano (o perché uno sembra più pertinente dell'altro).
    2. SELEZIONE PRINCIPALE: Indica qual è l'ID (T o CWE) più verosimile in assoluto.
    3. SCENARIO PREDITTIVO: Se l'attacco progredisce, cosa dobbiamo aspettarci?
    4. RISPOSTA ALL'INCIDENTE: Quali sono i primi 2 passi tecnici per contenere la minaccia?
    """

    print("🤖 Generazione report comparativo in corso...\n")
    response = llm.invoke(prompt)
    return response.content

# Test con il caso del crash User-Agent
test_input = "Il server web crasha quando invio una stringa di 5000 caratteri nel campo della testata HTTP User-Agent"
report = analyze_multi_hypothesis(test_input)
print(report)