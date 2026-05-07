import os
import re
from neo4j import GraphDatabase
from PyPDF2 import PdfReader
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

class CyberGraphIntegrator:
    def __init__(self, uri, user, password, model_name="llama3"):
        """Inizializza l'integratore basato su Graph RAG e Ollama."""
        self.url = "http://10.0.2.2:11434"
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
        # Configurazione LLM (Consigliato Llama3 per la tesi)
        self.llm = ChatOllama(
            model=model_name,
            temperature=0.1,
            base_url=self.url
        )
        
        # Regex per identificare tecniche MITRE nel codice/log
        self.re_mitre = re.compile(r"T\d{4}(?:\.\d{3})?")

    def close(self):
        self.driver.close()

    def _get_graph_context(self, found_ids):
        """Interroga Neo4j usando i 494 ponti di compliance e i 378 link tecnici."""
        knowledge_base = []
        with self.driver.session() as session:
            for tid in found_ids:
                # Query che attraversa la catena: Tecnica -> CWE -> Requirement
                query = """
                MATCH (t:Technique {id: $tid})
                OPTIONAL MATCH (t)-[:HAS_WEAKNESS]->(w:Weakness)
                OPTIONAL MATCH (t)-[:INFERRED_COMPLIANCE]->(r:Requirement)
                RETURN t.name as name,
                       collect(DISTINCT w.id) as weaknesses,
                       collect(DISTINCT r.standard + " (" + r.section + "): " + r.name) as compliance
                """
                res = session.run(query, tid=tid).single()
                if res:
                    info = f"--- DATI PER {tid} ({res['name']}) ---\n"
                    info += f"DEBOLEZZE: {', '.join(res['weaknesses']) if res['weaknesses'] else 'Nessuna'}\n"
                    info += f"VIOLAZIONI: {', '.join(res['compliance']) if res['compliance'] else 'Dato non presente'}\n"
                    knowledge_base.append(info)
        
        return "\n".join(knowledge_base)

    def _calculate_risk_score(self, context, analysis):
        """Score basato sulla densità delle relazioni nel grafo."""
        score = 0
        # Score basato sui 494 ponti di compliance attivati
        violations_count = len(re.findall(r"\[!\]|Violazione", context + analysis))
        score += min(violations_count * 15, 45)
        
        # Score basato sulle 378 relazioni HAS_WEAKNESS
        if "CWE-" in context: score += 25
        if "CRITICO" in analysis.upper(): score += 30
        
        final_score = min(score, 100)
        level = "CRITICO 🔴" if final_score >= 85 else "ALTO 🟠" if final_score >= 60 else "MEDIO 🟡" if final_score >= 30 else "BASSO 🟢"
        return final_score, level

    def analyze_path(self, path):
        """Legge file o intere cartelle e produce il report finale."""
        print(f"🔍 Scansione in corso su: {path}")
        raw_text = ""

        # Logica di lettura file/directory
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith(('.py', '.c', '.log', '.txt', '.sh')):
                        with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                            raw_text += f"\nFILE: {file}\n{f.read()}\n"
        elif path.endswith('.pdf'):
            reader = PdfReader(path)
            raw_text = "\n".join([p.extract_text() for p in reader.pages])
        else:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_text = f.read()

        # 1. Estrazione ID Tecnici
        found_ids = set(self.re_mitre.findall(raw_text))
        
        # 2. Arricchimento dal Grafo (Context Enrichment)
        graph_context = self._get_graph_context(found_ids)

        # 3. LangChain Generation
        prompt = ChatPromptTemplate.from_messages([
            ("system", "Sei un analista di Cyber Intelligence. Usa i dati del Knowledge Graph per validare le minacce."),
            ("user", "REPORT TECNICO:\n{text}\n\nDATI DAL GRAFO:\n{context}\n\nGenera un'analisi in ITALIANO che spieghi la Kill Chain e le violazioni ISO/NIST.")
        ])
        
        chain = prompt | self.llm | StrOutputParser()
        analysis = chain.invoke({"text": raw_text[:4000], "context": graph_context})
        
        # 4. Scoring
        score, level = self._calculate_risk_score(graph_context, analysis)
        
        return analysis, score, level, found_ids

if __name__ == "__main__":
    # Configurazione (Usa le tue credenziali Neo4j)
    integrator = CyberGraphIntegrator("bolt://10.0.2.2:7687", "neo4j", "***REMOVED***", model_name="llama3")
    
    # Input: accetta cartella o file singolo
    target = "../testing/vulnerable.c" 
    
    report, score, level, ids = integrator.analyze_path(target)
    
    print("\n" + "="*60)
    print(f"🛡️ LIVELLO DI RISCHIO: {level} ({score}/100)")
    print(f"🆔 TECNICHE RILEVATE: {', '.join(ids)}")
    print("="*60 + "\n")
    print(report)
    
    integrator.close()