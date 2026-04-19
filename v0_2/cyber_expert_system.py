import os
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_chroma import Chroma

class CyberThesisEngine:
    def __init__(self):
        self.embeddings = OllamaEmbeddings(model="mistral", base_url="http://10.0.2.2:11434")
        self.db = Chroma(persist_directory="./chroma_db", embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url="http://10.0.2.2:11434", temperature=0)

    def read_file(self, path):
        with open(path, 'r') as f:
            return f.read()

    def run_analysis(self, content, file_type="log/comando"):
        # 1. Recupero dal database
        docs = self.db.similarity_search(content, k=4)
        context = "\n".join([d.page_content for d in docs])

        # 2. Prompt Strutturato per la Tesi
        prompt = f"""
        [RUOLO]
        Sei un Senior Security Auditor e un esperto di Cyber Kill Chain. 
        Il tuo compito è l'analisi STATICA del codice per identificare pattern vulnerabili.

        [INPUT]
        CODICE SORGENTE: 
        {code_content}

        CONTESTO DI RIFERIMENTO (CWE e ATT&CK):
        {context}

        [ISTRUZIONI RIGIDE]
        1. ANALISI CODICE: Cerca nel codice C funzioni pericolose (strcpy, gets, etc). 
        2. MATCHING: Trova tra i dati del contesto la CWE che descrive esattamente l'errore nel codice.
        3. MAPPATURA: Collega la CWE alla fase della Cyber Kill Chain (es. Exploitation).
        4. PREDIZIONE: Se un attaccante sfrutta questa specifica CWE, quale sarà la mossa SUCCESSIVA? (es. Se c'è un overflow, cercherà di iniettare uno shellcode per una Reverse Shell).

        [FORMATO OUTPUT JSON]
        Rispondi ESCLUSIVAMENTE con un JSON strutturato così:
        {{
        "vulnerabilita_individuata": "CWE-ID e Nome",
        "punto_critico_codice": "la riga di codice incriminata",
        "fase_kill_chain": "...",
        "predizione_mossa_successiva": "...",
        "azione_di_mitigazione": "..."
        }}
        """
        
        return self.llm.invoke(prompt).content

# Esecuzione del test
if __name__ == "__main__":
    engine = CyberThesisEngine()
    risultato = engine.run_analysis("vulnerable.c")
    print("\n--- RISULTATO ANALISI ---")
    print(risultato)