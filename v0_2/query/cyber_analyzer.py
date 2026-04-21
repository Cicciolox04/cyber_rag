from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma

# Configurazione
URL_OLLAMA = "http://10.0.2.2:11434"
embeddings = OllamaEmbeddings(model="bge-m3", base_url=URL_OLLAMA)
db = Chroma(persist_directory="../chroma_db", embedding_function=embeddings)
llm = ChatOllama(model="mistral", base_url=URL_OLLAMA, temperature=0.1)

def analyze_and_predict(input_data):
    print(f"🔍 Analizzando l'input sospetto...")
    
    # Recuperiamo 4 documenti invece di 3 per avere un contesto più ampio (opzionale)
    docs = db.similarity_search(input_data, k=4)
    
    context_list = []
    for d in docs:
        # Recupero sicuro dei metadati
        name = d.metadata.get('name', 'Sconosciuto')
        phases = d.metadata.get('phases', 'N/A')
        item_id = d.metadata.get('id', 'N/A')
        
        info = f"[ID: {item_id}] Tecnica: {name} | Fasi: {phases}\nDescrizione: {d.page_content}"
        context_list.append(info)

    context = "\n---\n".join(context_list)

    prompt = f"""
    Sei un esperto di Cyber Threat Intelligence (CTI). Il tuo compito è analizzare il seguente input e mappare il comportamento:
    
    INPUT DA ANALIZZARE:
    '{input_data}'

    CONTESTO DA BASE DI CONOSCENZA (MITRE/CWE):
    {context}

    ISTRUZIONI:
    Analizza l'input e, basandoti sul contesto fornito, rispondi seguendo questo schema:
    1. IDENTIFICAZIONE: Quale tecnica o vulnerabilità è più probabile? Specifica l'ID (T o CWE).
    2. RAGIONAMENTO: Spiega brevemente perché l'input corrisponde a questo pattern.
    3. PREDIZIONE: Se l'attaccante ha successo con questa mossa ({input_data}), quale sarà il suo prossimo passo logico nella catena d'attacco?
    4. MITIGAZIONE: Fornisci una raccomandazione tecnica immediata.
    """

    print("🤖 Elaborazione analisi predittiva in corso...\n")
    response = llm.invoke(prompt)
    return response.content

# Esempio di esecuzione
test_input = "Il server web crasha quando invio una stringa di 5000 caratteri nel campo della testata HTTP User-Agent"
report = analyze_and_predict(test_input)
print(report)