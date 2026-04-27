import os
from PyPDF2 import PdfReader
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama

class CyberPredictiveIntegrator:
    def __init__(self, db_dir="../chroma_db", threshold=0.8):
        self.url = "http://10.0.2.2:11434"
        self.embeddings = OllamaEmbeddings(model="bge-m3", base_url=self.url)
        self.db = Chroma(persist_directory=db_dir, embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url=self.url, temperature=0.1)
        self.threshold = threshold

    def _calculate_risk_score(self, rag_evidence, ll_analysis):
        score = 0
        # 1. Punteggio base per evidenze RAG (Confidenza)
        evidences = [e for e in rag_evidence.split('\n\n') if e.strip()]
        score += min(len(evidences) * 10, 30) 

        # 2. Moltiplicatori di Gravità (Impatto)
        severity_map = {
            "RCE": 40, "Remote Code Execution": 40, "Command Injection": 40,
            "Supply Chain": 30, "Lateral Movement": 25,
            "Hardcoded": 20, "Plaintext": 20,
            "Unverified": 15, "HTTP": 10
        }
        
        for term, weight in severity_map.items():
            if term.lower() in ll_analysis.lower() or term.lower() in rag_evidence.lower():
                score += weight
        
        # 3. Bonus per Correlazione (se l'analisi cita più file)
        if "connessione tra i file" in ll_analysis.lower() or "catena" in ll_analysis.lower():
            score += 15

        final_score = min(score, 100)
        
        if final_score >= 85: level = "CRITICO 🔴"
        elif final_score >= 60: level = "ALTO 🟠"
        elif final_score >= 30: level = "MEDIO 🟡"
        else: level = "BASSO 🟢"
        
        return final_score, level

    def _smart_retrieval(self, text_segment):
        results = self.db.similarity_search_with_score(text_segment, k=6)
        valid_context = []
        for doc, score in results:
            if score <= self.threshold:
                type_label = doc.metadata.get('type', 'N/A').upper()
                id_label = doc.metadata.get('id', 'N/A')
                valid_context.append(f"[{type_label}] {id_label}: {doc.page_content}")
        return "\n\n".join(valid_context)

    def analyze_security_report(self, path):
        print(f"🔍 Analisi in corso su: {path}")
        content = ""

        # Caso 1: Il percorso fornito è una directory
        if os.path.isdir(path):
            print(f"📁 Rilevata cartella. Aggregazione dei file tecnici...")
            for root, _, files in os.walk(path):
                # Escludiamo cartelle di sistema o cache
                for file in files:
                    if file.endswith(('.py', '.json', '.txt', '.log', '.md')):
                        file_full_path = os.path.join(root, file)
                        try:
                            with open(file_full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content += f"\n--- NOME FILE: {file} ---\n{f.read()}\n"
                        except Exception as e:
                            print(f"⚠️ Errore lettura {file}: {e}")
        
        # Caso 2: Il percorso è un file PDF
        elif path.endswith('.pdf'):
            reader = PdfReader(path)
            content = "\n".join([p.extract_text() for p in reader.pages])
        
        # Caso 3: Il percorso è un file di testo singolo
        else:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

        if not content:
            return "Nessun dato utile trovato.", 0, "N/A"

        # RAG e analisi predittiva
        rag_evidence = self._smart_retrieval(content[:3000])
        
        prompt = f"""
        [RUOLO: Senior Cyber Threat Intelligence Analyst]
        CONTESTO MULTI-FILE RILEVATO:
        {content[:5000]}
        
        EVIDENZE RAG (CWE/MITRE):
        {rag_evidence}
        
        COMPITO:
        1. RICONOSCIMENTO PATTERN: Collega le falle tra i diversi file (es. config -> codice -> log).
        2. SCENARIO PREVISTO: Descrivi la Kill Chain completa (Supply Chain Attack, Lateral Movement).
        3. PRIORITÀ DI INTERVENTO: Qual è l'anello più debole della catena?
        4. FORNISCI UNA MITIGAZIONE TECNICA: basati sulle CWE presenti nel database per forinre una mitigazione, se non la trovi NON INVENTARE.
        """
        
        analysis = self.llm.invoke(prompt).content
        numeric_score, risk_level = self._calculate_risk_score(rag_evidence, analysis)
        
        return analysis, numeric_score, risk_level

if __name__ == "__main__":
    predictor = CyberPredictiveIntegrator()
    report_text, score, level = predictor.analyze_security_report("../testing/vulnerable/vulnerable.c")
    
    print("\n" + "="*50)
    print(f"🛡️ ANALISI COMPLETATA - LIVELLO DI RISCHIO: {level}")
    print(f"📊 SCORE NUMERICO: {score}/100")
    print("="*50)
    print(report_text)