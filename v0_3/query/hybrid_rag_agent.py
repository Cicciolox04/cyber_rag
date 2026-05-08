import os
import warnings
import logging
from pathlib import Path
from neo4j import GraphDatabase
from langchain_community.vectorstores import Neo4jVector
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# 🚫 Silenziamento warning e log
warnings.filterwarnings("ignore", category=UserWarning, message=".*db.index.vector.queryNodes.*")
logging.getLogger("neo4j").setLevel(logging.ERROR)

class HybridRAGAnalystAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.auth = (user, password)
        self.neo4j_url = uri
        self.embeddings = OllamaEmbeddings(model="nomic-embed-text", base_url=ollama_url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=ollama_url)
        
        self.vector_tech = self._init_vs("cyber_vector_index", "Technique")
        self.vector_weak = self._init_vs("weakness_vector_index", "Weakness")
        self.driver = GraphDatabase.driver(uri, auth=self.auth, notifications_min_severity="OFF")

    def _init_vs(self, index_name, label):
        return Neo4jVector.from_existing_graph(
            embedding=self.embeddings, url=self.neo4j_url, 
            username=self.auth[0], password=self.auth[1],
            index_name=index_name, node_label=label,
            text_node_properties=["description"], embedding_node_property="embedding",
            retrieval_query="RETURN node.description AS text, score, node {.*, graph_id: node.id, label: labels(node)[0]} AS metadata"
        )

    def _get_compliance_context(self, entities):
        """Naviga i 395 ponti di compliance verso ISO/NIST."""
        context = []
        with self.driver.session() as session:
            for ent in entities:
                query = """
                MATCH (n) WHERE n.id = $id
                OPTIONAL MATCH (n)-[:HAS_WEAKNESS|VIOLATES|INFERRED_COMPLIANCE*1..2]->(r:Requirement)
                RETURN n.id as id, n.name as name, labels(n)[0] as type,
                       collect(DISTINCT r.standard + ' ' + r.section + ': ' + r.name) as compliance
                """
                res = session.run(query, id=ent['id']).single()
                if res and res['compliance']:
                    context.append(f"[{res['type']} {res['id']}] {res['name']}\nNorme: {res['compliance']}")
        return "\n".join(context)

    def analyze_content(self, path_str):
        """Punto di ingresso dinamico per File o Cartelle."""
        path = Path(path_str)
        workspace_data = {}

        # 1. Caricamento Dati
        if path.is_file():
            print(f"🔍 Analisi File Singolo: {path.name}")
            with open(path, 'r') as f: workspace_data[path.name] = f.read()
        else:
            print(f"📁 Analisi Workspace: {path.name}")
            for f_path in path.rglob('*'):
                if f_path.is_file() and f_path.suffix in ['.py', '.c', '.cpp', '.h', '.js']:
                    with open(f_path, 'r') as f: workspace_data[f_path.name] = f.read()

        # 2. Estrazione Concetto Globale (Chain of Risk)
        full_context = "\n".join([f"--- FILE: {n} ---\n{c}" for n, c in workspace_data.items()])
        concept_prompt = ChatPromptTemplate.from_messages([
            ("system", "Sei un Security Architect. Identifica la catena di rischio che collega questi file. Descrivi la vulnerabilità principale in una frase."),
            ("user", "CODICE:\n{code}")
        ])
        concept = (concept_prompt | self.llm | StrOutputParser()).invoke({"code": full_context[:6000]})
        print(f"🎯 Concetto rilevato: {concept}")

        # 3. Ricerca nel Grafo (MITRE + CWE)
        docs = self.vector_tech.similarity_search(concept, k=2) + self.vector_weak.similarity_search(concept, k=2)
        entities = [{'id': d.metadata['graph_id'], 'label': d.metadata['label']} for d in docs]
        
        # 4. Recupero Compliance e Report
        graph_data = self._get_compliance_context(entities)
        report_prompt = ChatPromptTemplate.from_messages([
            ("system", "Sei un Senior Security Architect. Rispondi in ITALIANO citando i controlli NIST/ISO del grafo."),
            ("user", "CONTESTO GRAFO:\n{context}\n\nCONCETTO RILEVATO: {concept}")
        ])
        report = (report_prompt | self.llm | StrOutputParser()).invoke({"context": graph_data, "concept": concept})
        
        return report, entities

    def close(self):
        self.driver.close()

if __name__ == "__main__":
    analyst = HybridRAGAnalystAgent("bolt://10.0.2.2:7687", "neo4j", "ciaociao", "http://10.0.2.2:11434")
    try:
        # Ora puoi passare sia un file che una cartella senza errori!
        report, found = analyst.analyze_content("../testing/test_repo/")
        print("\n" + "="*20 + " RISULTATI " + "="*20 + f"\n{report}")
    finally:
        analyst.close()