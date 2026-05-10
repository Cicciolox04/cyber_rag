import os
import warnings
import logging
from pathlib import Path
from neo4j import GraphDatabase
from langchain_community.vectorstores import Neo4jVector
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

warnings.filterwarnings("ignore")
logging.getLogger("neo4j").setLevel(logging.ERROR)

class HybridRAGAnalystAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.auth = (user, password)
        self.neo4j_url = uri
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=ollama_url)
        
        # Inizializzazione Prompt come attributi della classe
        self.concept_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un esperto di Cyber Security. Analizza il codice e descrivi brevemente l'azione tecnica 
            usando terminologia standard (es. 'Hardcoded Credentials', 'SSRF', 'SQL Injection').
            """),
            ("user", "CODICE DA ANALIZZARE:\n{code}")
        ])

        self.report_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un Senior Security Architect. Riceverai un elenco di possibili vulnerabilità dal grafo. Genera un report in ITALIANO.
            
            IL TUO COMPITO:
            1. Confronta il 'CONCETTO TECNICO' con le 'DEFINIZIONI' del grafo.
            2. Seleziona la SINGOLA Weakness (CWE) e la SINGOLA Technique (MITRE) che meglio descrivono il rischio reale.
            3. Non creare una lista di 10 punti. Scrivi un'analisi coesa.
            4. Cita esplicitamente gli ID selezionati e i controlli NIST/ISO associati nel grafo.
            
            Se trovi ID molto simili (es. CWE-798 e CWE-259), scegli quello che appare più completo nel contesto del grafo."""),
            ("user", "CONTESTO DAL GRAFO:\n{context}\n\nCONCETTO TECNICO:\n{concept}")
        ])

        self.vector_tech = self._init_vs("cyber_vector_index", "Technique")
        self.vector_weak = self._init_vs("weakness_vector_index", "Weakness")
        self.driver = GraphDatabase.driver(uri, auth=self.auth)

    def _init_vs(self, index_name, label):
        return Neo4jVector.from_existing_graph(
            embedding=self.embeddings, url=self.neo4j_url, 
            username=self.auth[0], password=self.auth[1],
            index_name=index_name, node_label=label,
            text_node_properties=["description"], embedding_node_property="embedding",
            retrieval_query="RETURN node.description AS text, score, node {.*, graph_id: node.id, label: labels(node)[0]} AS metadata"
        )

    def _get_compliance_context(self, entities):
        context = []
        with self.driver.session() as session:
            for ent in entities:
                query = """
                MATCH (n) WHERE n.id = $id
                OPTIONAL MATCH (n)-[:HAS_WEAKNESS|VIOLATES|INFERRED_COMPLIANCE*1..2]->(r:Requirement)
                RETURN n.id as id, n.name as name, labels(n)[0] as type, n.description as desc,
                       collect(DISTINCT r.standard + ' ' + r.section + ': ' + r.name) as compliance
                """
                res = session.run(query, id=ent['id']).single()
                if res:
                    comp = ", ".join(res['compliance']) if res['compliance'] else "Nessuna norma mappata"
                    context.append(f"🔍 [{res['type']}] {res['id']}: {res['name']}\nDEF: {res['desc']}\nNORME: {comp}")
        return "\n\n".join(context)

    def analyze_content(self, path_str):
        path = Path(path_str)
        workspace_data = {}

        files = list(path.rglob('*')) if path.is_dir() else [path]
        for f_path in files:
            if f_path.is_file() and f_path.suffix in ['.py', '.c', '.cpp', '.h', '.js']:
                with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                    workspace_data[f_path.name] = f.read()

        if not workspace_data: return "Nessun file trovato.", []

        full_context = "\n".join([f"--- FILE: {n} ---\n{c}" for n, c in workspace_data.items()])

        # 1. Estrazione Concetto
        concept = (self.concept_prompt | self.llm | StrOutputParser()).invoke({"code": full_context[:8000]})
        print(f"🎯 Concetto tecnico: {concept[:150]}...")

        # 2. Ricerca Semantica (Aumentiamo k a 10 per le Weakness per non perdere CWE-798)
        tech_docs = self.vector_tech.similarity_search(concept, k=3)
        weak_docs = self.vector_weak.similarity_search(concept, k=10)
        
        entities = [{'id': d.metadata['graph_id'], 'label': d.metadata['label']} for d in (tech_docs + weak_docs)]
        print(f"🔗 ID trovati: {[e['id'] for e in entities]}")

        # 3. Report Finale
        graph_data = self._get_compliance_context(entities)
        report = (self.report_prompt | self.llm | StrOutputParser()).invoke({
            "context": graph_data, 
            "concept": concept
        })
        return report, entities

    def close(self):
        self.driver.close()

if __name__ == "__main__":
    analyst = HybridRAGAnalystAgent("bolt://10.0.2.2:7687", "neo4j", "ciaociao", "http://10.0.2.2:11434")
    try:
        # Test sul file delle credenziali
        report, found = analyst.analyze_content("../testing/complex_scenario")
        print("\n" + "═"*30 + " REPORT FINALE " + "═"*30 + f"\n{report}\n" + "═"*75)
    finally:
        analyst.close()