import os
import json
import re
from PyPDF2 import PdfReader
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama

class CyberPredictiveIntegrator:
    def __init__(self, db_dir=None, map_path=None, threshold=0.8):
        # 1. Definizione immediata dei percorsi per evitare AttributeError
        current_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.abspath(os.path.join(current_dir, ".."))
        
        self.db_dir = db_dir or os.path.join(base_dir, "chroma_db")
        self.map_path = map_path or os.path.join(base_dir, "data", "opencre_map.json")
        self.threshold = threshold
        self.url = "http://10.0.2.2:11434" # Indirizzo standard per Ollama su Linux/Windows

        # 2. Inizializzazione modelli e DB
        try:
            self.embeddings = OllamaEmbeddings(model="bge-m3", base_url=self.url)
            self.llm = ChatOllama(model="mistral", base_url=self.url, temperature=0.1)
            
            # Connessione al database vettoriale
            self.db = Chroma(persist_directory=self.db_dir, embedding_function=self.embeddings)
            
            # Caricamento Mappa OpenCRE
            if os.path.exists(self.map_path):
                with open(self.map_path, "r", encoding="utf-8") as f:
                    self.opencre_data = json.load(f)
                print(f"✅ Mappa OpenCRE caricata ({len(self.opencre_data)} collegamenti)")
            else:
                self.opencre_data = {}
                print(f"⚠️ Mappa non trovata in {self.map_path}")
                
        except Exception as e:
            print(f"❌ Errore inizializzazione: {e}")
            raise e

    def _smart_retrieval(self, text_segment):
        """Ricerca nel DB e logga i risultati nel terminale."""
        results = self.db.similarity_search_with_score(text_segment, k=6)
        valid_context, found_ids = [], []
        
        print(f"\n--- DEBUG RETRIEVAL (Soglia: {self.threshold}) ---")
        for doc, score in results:
            print(f"Documento trovato - Score: {score:.4f}")
            if score <= self.threshold:
                type_label = doc.metadata.get('type', 'N/A').upper()
                id_label = doc.metadata.get('id', 'N/A')
                if id_label != 'N/A':
                    found_ids.append(f"{type_label}: {id_label}")
                valid_context.append(f"[{type_label}] {id_label}: {doc.page_content}")
        
        return "\n\n".join(valid_context), list(set(found_ids))

    def _get_compliance_info(self, found_ids):
        """Mappa gli ID verso gli standard OpenCRE."""
        compliance_list = []
        for id_entry in found_ids:
            try:
                clean_id = id_entry.split(": ")[1]
                if clean_id in self.opencre_data:
                    for mapping in self.opencre_data[clean_id]:
                        compliance_list.append(f"- {clean_id} viola {mapping['standard']} ({mapping['section']}) -> CRE: {mapping['cre_name']}")
            except: continue
        return "\n".join(list(set(compliance_list)))

    def parse_sections(self, text):
        """Suddivide l'output dell'LLM nei tag specifici."""
        sections = {"PATTERN": "N/D", "IDENTIFICATIVI": "N/D", "CONFORMITA": "N/D", "MITIGAZIONE": "N/D"}
        patterns = {
            "PATTERN": r"\[PATTERN\](.*?)\[IDENTIFICATIVI\]",
            "IDENTIFICATIVI": r"\[IDENTIFICATIVI\](.*?)\[CONFORMITA\]",
            "CONFORMITA": r"\[CONFORMITA\](.*?)\[MITIGAZIONE\]",
            "MITIGAZIONE": r"\[MITIGAZIONE\](.*?)$"
        }
        for key, reg in patterns.items():
            match = re.search(reg, text, re.DOTALL)
            if match: sections[key] = match.group(1).strip()
        return sections

    def analyze_security_report(self, all_files):
        """Processa i file e genera l'analisi."""
        content = ""
        for file_obj in all_files:
            path = file_obj.name
            if path.endswith('.pdf'):
                reader = PdfReader(path)
                content += "\n".join([p.extract_text() for p in reader.pages])
            else:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content += f"\n--- FILE: {os.path.basename(path)} ---\n{f.read()}\n"

        if not content: return {}, []

        # Retrieval e Compliance
        rag_evidence, ids_list = self._smart_retrieval(content[:4000])
        compliance_text = self._get_compliance_info(ids_list)
        
        prompt = f"""
        [RUOLO: Senior Cyber Threat Intelligence Analyst]
        [ISTRUZIONI: Rispondi in ITALIANO. Usa i tag indicati.]
        CONTESTO: {content[:4000]}
        EVIDENZE RAG: {rag_evidence}
        CONFORMITÀ: {compliance_text}
        
        Analisi:
        [PATTERN] ...
        [IDENTIFICATIVI] ...
        [CONFORMITA] ...
        [MITIGAZIONE] ...
        """
        raw_analysis = self.llm.invoke(prompt).content
        return self.parse_sections(raw_analysis), ids_list