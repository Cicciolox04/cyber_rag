import os
import warnings
import logging
from pathlib import Path
from neo4j import GraphDatabase
from langchain_community.vectorstores import Neo4jVector
from langchain_ollama import OllamaEmbeddings, ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# 🔇 Pulizia output
warnings.filterwarnings("ignore")
logging.getLogger("neo4j").setLevel(logging.ERROR)

class HybridRAGAnalystAgent:
    def __init__(self, uri, user, password, ollama_url):
        self.auth = (user, password)
        self.neo4j_url = uri
        # Usiamo mxbai per la massima precisione semantica (1024 dimensioni)
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=ollama_url)
        
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
        """Recupera la catena di compliance dal grafo per le entità trovate."""
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

        # 1. Caricamento Sorgenti
        files = list(path.rglob('*')) if path.is_dir() else [path]
        for f_path in files:
            if f_path.is_file() and f_path.suffix in ['.py', '.c', '.cpp', '.h', '.js']:
                with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                    workspace_data[f_path.name] = f.read()

        if not workspace_data:
            return "Nessun file supportato trovato.", []

        full_context = "\n".join([f"--- FILE: {n} ---\n{c}" for n, c in workspace_data.items()])

        # 2. Estrazione Concetto (Chain of Risk) - QUI DEFINIAMO 'concept'
        concept_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un Security Architect. Analizza il codice e descrivi il rischio principale. 
            Sii estremamente preciso sui flussi di dati (chi controlla cosa, dove va l'input)."""),
            ("user", "CODICE:\n{code}")
        ])
        # La variabile 'concept' nasce qui
        concept = (concept_prompt | self.llm | StrOutputParser()).invoke({"code": full_context[:8000]})
        print(f"🎯 Analisi preliminare: {concept[:150]}...")

        # 3. Ricerca nel Grafo (k=5 per dare ampiezza alla generalizzazione)
        tech_docs = self.vector_tech.similarity_search(concept, k=3)
        weak_docs = self.vector_weak.similarity_search(concept, k=5)
        
        entities = [{'id': d.metadata['graph_id'], 'label': d.metadata['label']} for d in (tech_docs + weak_docs)]
        
        # 4. Report Finale con Ragionamento Critico
        graph_data = self._get_compliance_context(entities)
        report_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un Senior Security Architect. Genera un report professionale in ITALIANO.
            
            REGOLE DI RAGIONAMENTO:
            1. Confronta il 'FLUSSO DEL CODICE' con le 'DEFINIZIONI TECNICHE' del grafo.
            2. Se trovi più vulnerabilità simili, seleziona quella che descrive meglio il comportamento (es. distingue tra richieste fatte dal client e richieste fatte dal server).
            3. Cita sempre i controlli NIST/ISO associati ai nodi del grafo."""),
            ("user", "DATI DAL GRAFO:\n{context}\n\nFLUSSO DEL CODICE:\n{concept}")
        ])
        
        report = (report_prompt | self.llm | StrOutputParser()).invoke({"context": graph_data, "concept": concept})
        return report, entities

    def close(self):
        self.driver.close()

if __name__ == "__main__":
    analyst = HybridRAGAnalystAgent("bolt://10.0.2.2:7687", "neo4j", "ciaociao", "http://10.0.2.2:11434")
    try:
        # Puntiamo alla cartella di test
        report, found = analyst.analyze_content("../testing/hardcoded_creds.py")
        print("\n" + "═"*25 + " REPORT FINALE " + "═"*25 + f"\n{report}\n" + "═"*65)
    finally:
        analyst.close()