import os
import json
import re
from PyPDF2 import PdfReader
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings, ChatOllama

class CyberPredictiveIntegrator:
    def __init__(self, db_dir="../chroma_db", threshold=1.5, map_path="../data/opencre_map.json"):
        self.url = "http://10.0.2.2:11434"
        self.embeddings = OllamaEmbeddings(model="bge-m3", base_url=self.url)
        self.db = Chroma(persist_directory=db_dir, embedding_function=self.embeddings)
        self.llm = ChatOllama(model="mistral", base_url=self.url, temperature=0.1)
        self.threshold = threshold
        
        if os.path.exists(map_path):
            with open(map_path, "r", encoding="utf-8") as f:
                self.opencre_data = json.load(f)

    def _read_single_file(self, file_path):
        """Legge il contenuto di un file (PDF o Testo)."""
        try:
            if file_path.lower().endswith('.pdf'):
                reader = PdfReader(file_path)
                return "\n".join([p.extract_text() for p in reader.pages if p.extract_text()])
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f"\n--- FILE: {os.path.basename(file_path)} ---\n{f.read()[:2000]}\n"
        except: return ""

    def analyze_security_report(self, input_data):
        """Analizza una lista di oggetti file forniti da Gradio."""
        content = ""
        
        # input_data sarà una lista di file caricati tramite Gradio
        if isinstance(input_data, list):
            for file_obj in input_data:
                content += self._read_single_file(file_obj.name)
        
        if not content: return None, []

        # RAG e LLM
        try:
            results = self.db.similarity_search_with_score(content[:3000], k=10)
            ids_list = list(set([d.metadata.get('id') for d, s in results if s <= self.threshold and d.metadata.get('id')]))
            
            prompt = f"[RUOLO: Senior Analyst] - CONTESTO: {content[:4500]} - EVIDENZE RAG: {ids_list}\n\nAnalizza usando i tag [PATTERN], [KILLCHAIN], [IDENTIFICATIVI], [CONFORMITA], [MITIGAZIONE]."
            response = self.llm.invoke(prompt).content
            
            def extract(tag, next_tag=None):
                p = rf"\[{tag}\](.*?)(?=\[{next_tag}\]|$)" if next_tag else rf"\[{tag}\](.*)$"
                m = re.search(p, response, re.S | re.I)
                return m.group(1).strip() if m else "Non rilevato."

            data = {
                "pattern": extract("PATTERN", "KILLCHAIN"),
                "killchain": extract("KILLCHAIN", "IDENTIFICATIVI"),
                "ids": extract("IDENTIFICATIVI", "CONFORMITA"),
                "conformita": extract("CONFORMITA", "MITIGAZIONE"),
                "mitigazione": extract("MITIGAZIONE")
            }
            return data, ids_list
        except: return None, []