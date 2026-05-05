import os
import json
from PyPDF2 import PdfReader
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama

class CyberPredictiveIntegrator:
    def __init__(self, db_dir="../chroma_db", threshold=0.8, map_path="../data/opencre_map.json"):
        """Inizializza il sistema RAG con supporto OpenCRE per la conformità."""
        self.url = "http://10.0.2.2:11434"
        self.embeddings = OllamaEmbeddings(model="bge-m3", base_url=self.url)
        self.db = Chroma(persist_directory=db_dir, embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url=self.url, temperature=0.1)
        self.threshold = threshold
        
        # Caricamento Mappa OpenCRE (Knowledge Graph deterministico)
        if os.path.exists(map_path):
            with open(map_path, "r", encoding="utf-8") as f:
                self.opencre_data = json.load(f)
            print(f"✅ Mappa OpenCRE caricata correttamente ({len(self.opencre_data)} collegamenti)")
        else:
            self.opencre_data = {}
            print(f"⚠️ Attenzione: File {map_path} non trovato. La conformità sarà disabilitata.")

    def _calculate_risk_score(self, rag_evidence, ll_analysis):
        """Calcola uno score numerico basato sulle evidenze trovate."""
        score = 0
        evidences = [e for e in rag_evidence.split('\n\n') if e.strip()]
        score += min(len(evidences) * 10, 30) 

        severity_map = {
            "RCE": 40, "Remote Code Execution": 40, "Command Injection": 40,
            "SQL Injection": 40, "Hardcoded": 25, "Plaintext": 20,
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

    def _smart_retrieval(self, text_segment):
        """Recupera documenti dal DB vettoriale e isola gli ID (CWE, MITRE, CAPEC)."""
        results = self.db.similarity_search_with_score(text_segment, k=6)
        valid_context = []
        found_ids = []

        for doc, score in results:
            if score <= self.threshold:
                type_label = doc.metadata.get('type', 'N/A').upper()
                id_label = doc.metadata.get('id', 'N/A')
                
                if id_label != 'N/A':
                    found_ids.append(f"{type_label}: {id_label}")
                
                valid_context.append(f"[{type_label}] {id_label}: {doc.page_content}")
        
        return "\n\n".join(valid_context), list(set(found_ids))

    def _get_compliance_info(self, found_ids):
        """Mappa gli ID tecnici verso gli standard internazionali via OpenCRE."""
        compliance_list = []
        for id_entry in found_ids:
            try:
                # Estrazione ID pulito (es. "CWE-943")
                clean_id = id_entry.split(": ")[1]
                if clean_id in self.opencre_data:
                    for mapping in self.opencre_data[clean_id]:
                        info = (f"- {clean_id} viola {mapping['standard']} "
                                f"(Sezione {mapping['section']}) -> "
                                f"Requisito CRE: {mapping['cre_name']}")
                        compliance_list.append(info)
            except: continue
            
        return "\n".join(list(set(compliance_list)))

    def analyze_security_report(self, path):
        """Esegue l'analisi completa di una repository o di un file."""
        print(f"🔍 Analisi in corso su: {path}")
        content = ""

        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(('.py', '.sh', '.json', '.txt', '.log', '.md', '.csv')):
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

        # 1. Recupero evidenze tecniche (RAG)
        rag_evidence, ids_list = self._smart_retrieval(content[:4000])
        
        # 2. Arricchimento con conformità OpenCRE
        compliance_text = self._get_compliance_info(ids_list)
        
        # 3. Generazione Analisi con LLM
        prompt = f"""
        [RUOLO: Senior Cyber Threat Intelligence Analyst]
        [ISTRUZIONI: Rispondi SEMPRE in ITALIANO]
        
        CONTESTO RILEVATO DALLA REPOSITORY:
        {content[:5000]}
        
        EVIDENZE TECNICHE (CWE/MITRE/CAPEC):
        {rag_evidence}
        
        RIFERIMENTI DI CONFORMITÀ (OpenCRE):
        {compliance_text if compliance_text else "Nessuna mappatura di conformità trovata per gli ID rilevati."}
        
        COMPITO:
        1. RICONOSCIMENTO PATTERN: Spiega come le falle interagiscono tra i diversi file.
        2. SCENARIO PREVISTO: Descrivi la Kill Chain completa dell'attacco.
        3. LISTA IDENTIFICATIVI: Elenca ogni CWE, MITRE ATT&CK e CAPEC pertinente.
        4. CONFORMITÀ E STANDARD: Utilizzando i dati OpenCRE, specifica quali Standard internazionali (ISO 27001, NIST 800-53, OWASP) sono violati.
        5. MITIGAZIONE: Fornisci una strategia di mitigazione tecnica basata sulle vulnerabilità trovate.
        """
        
        analysis = self.llm.invoke(prompt).content
        numeric_score, risk_level = self._calculate_risk_score(rag_evidence, analysis)
        
        return analysis, numeric_score, risk_level, ids_list

if __name__ == "__main__":
    predictor = CyberPredictiveIntegrator()
    
    # Percorso del test case
    target_path = "../testing/vulnerable/final_stress_test"
    
    report_text, score, level, found_ids = predictor.analyze_security_report(target_path)
    
    print("\n" + "="*60)
    print(f"🛡️ LIVELLO DI RISCHIO: {level} ({score}/100)")
    print("="*60)
    
    print("\n📚 RIFERIMENTI E MAPPATURE:")
    if found_ids:
        for ref_id in found_ids:
            print(f"  • {ref_id}")
    else:
        print("  • Nessun riferimento specifico trovato.")

    print("\n📝 ANALISI DETTAGLIATA:")
    print("-" * 60)
    print(report_text)