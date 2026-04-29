import os
from PyPDF2 import PdfReader
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama

class CyberPredictiveIntegrator:
    def __init__(self, db_dir="../chroma_db", threshold=0.85): # Soglia leggermente più permissiva per i CAPEC
        self.url = "http://10.0.2.2:11434"
        self.embeddings = OllamaEmbeddings(model="bge-m3", base_url=self.url)
        self.db = Chroma(persist_directory=db_dir, embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url=self.url, temperature=0.1)
        self.threshold = threshold

    def _calculate_risk_score(self, rag_evidence, ll_analysis):
        score = 0
        evidences = [e for e in rag_evidence.split('\n\n') if e.strip()]
        score += min(len(evidences) * 10, 30) 

        severity_map = {
            "RCE": 40, "Remote Code Execution": 40, "Command Injection": 40,
            "Supply Chain": 30, "Lateral Movement": 25,
            "Hardcoded": 20, "Plaintext": 20,
            "Unverified": 15, "HTTP": 10
        }
        
        for term, weight in severity_map.items():
            if term.lower() in ll_analysis.lower() or term.lower() in rag_evidence.lower():
                score += weight
        
        if "connessione tra i file" in ll_analysis.lower() or "catena" in ll_analysis.lower():
            score += 15

        final_score = min(score, 100)
        level = "CRITICO 🔴" if final_score >= 85 else "ALTO 🟠" if final_score >= 60 else "MEDIO 🟡" if final_score >= 30 else "BASSO 🟢"
        
        return final_score, level

    def _smart_retrieval(self, query):
        """
        Recupero bilanciato: interroga separatamente le categorie per non 'oscurare' i CAPEC.
        """
        # Interrogazioni mirate per categoria
        m = self.db.similarity_search_with_score(query, k=3, filter={"type": "mitre_technique"})
        c = self.db.similarity_search_with_score(query, k=3, filter={"type": "cwe_weakness"})
        ca = self.db.similarity_search_with_score(query, k=4, filter={"type": "capec_pattern"})
        
        all_results = m + c + ca
        valid_context = []
        found_ids = []

        for doc, score in all_results:
            if score <= self.threshold:
                type_label = doc.metadata.get('type', 'N/A').upper()
                id_label = doc.metadata.get('id', 'N/A')
                
                if id_label != 'N/A':
                    found_ids.append(f"{type_label}: {id_label}")
                
                valid_context.append(f"[{type_label}] {id_label}: {doc.page_content}")
        
        return "\n\n".join(valid_context), list(set(found_ids))

    def analyze_security_report(self, path):
        print(f"🔍 Analisi in corso su: {path}")
        content = ""

        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(('.py', '.json', '.txt', '.log', '.md', '.c', '.h')):
                        try:
                            with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                                content += f"\n--- NOME FILE: {file} ---\n{f.read()}\n"
                        except: pass
        elif path.endswith('.pdf'):
            reader = PdfReader(path)
            content = "\n".join([p.extract_text() for p in reader.pages])
        else:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

        if not content:
            return "Nessun dato trovato.", 0, "N/A", []

        # FASE 1: Generazione descrizione tecnica intermedia (HyDE) per attivare i CAPEC
        hyde_prompt = f"Analizza e descrivi la vulnerabilità, il pattern d'attacco e l'obiettivo tattico di: {content[:2000]}"
        hyde_desc = self.llm.invoke(hyde_prompt).content

        # FASE 2: Retrieval bilanciato usando la descrizione HyDE
        rag_evidence, ids_list = self._smart_retrieval(hyde_desc)
        
        prompt = f"""
        [RUOLO: Senior Cyber Threat Intelligence Analyst]
        [ISTRUZIONI: Rispondi SEMPRE in ITALIANO]
        
        CONTESTO RILEVATO:
        {content[:5000]}
        
        EVIDENZE RAG (CWE/MITRE/CAPEC):
        {rag_evidence}
        
        COMPITO:
        1. RICONOSCIMENTO PATTERN: Collega le falle tra i diversi file.
        2. SCENARIO PREVISTO: Descrivi la Kill Chain completa.
        3. LISTA IDENTIFICATIVI: Cita e spiega esplicitamente ogni CWE, MITRE e CAPEC trovato nel database.
        4. MITIGAZIONE: Fornisci una mitigazione tecnica basata sulle CWE trovate.
        """
        
        analysis = self.llm.invoke(prompt).content
        numeric_score, risk_level = self._calculate_risk_score(rag_evidence, analysis)
        
        return analysis, numeric_score, risk_level, ids_list

if __name__ == "__main__":
    predictor = CyberPredictiveIntegrator()
    # Eseguiamo l'analisi sulla cartella test_repo
    report_text, score, level, found_ids = predictor.analyze_security_report("../testing/vulnerable/hardcoded_creds.py")
    
    print("\n" + "="*50)
    print(f"🛡️ LIVELLO DI RISCHIO: {level} ({score}/100)")
    print("="*50)
    
    print("\n📚 RIFERIMENTI TROVATI NEL DATABASE (Mappatura Standard):")
    if found_ids:
        for ref_id in sorted(found_ids):
            print(f"  • {ref_id}")
    else:
        print("  • Nessun riferimento specifico trovato.")

    print("\n📝 ANALISI DETTAGLIATA:")
    print("-" * 50)
    print(report_text)