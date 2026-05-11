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
        # Utilizziamo lo stesso modello di embedding usato per l'indicizzazione
        self.embeddings = OllamaEmbeddings(model="mxbai-embed-large", base_url=ollama_url)
        self.llm = ChatOllama(model="llama3", temperature=0, base_url=ollama_url)
        
        self.concept_prompt = ChatPromptTemplate.from_messages([
            ("system", "Sei un esperto di Cyber Security. Analizza il codice e descrivi l'azione tecnica usando terminologia standard."),
            ("user", "CODICE DA ANALIZZARE:\n{code}")
        ])

        self.report_prompt = ChatPromptTemplate.from_messages([
            ("system", """Sei un Senior Security Architect. Genera un report in ITALIANO.
            1. Analizza i dati del grafo (Exploit, CVE, CWE, Requisiti NIST/ISO).
            2. Spiega come un exploit reale trovato nel sistema possa violare norme specifiche.
            3. Cita gli ID (CWE-XXX, CVE-YYYY-XXXX) e i nomi dei file exploit se presenti."""),
            ("user", "CONTESTO DAL GRAFO:\n{context}\n\nCONCETTO TECNICO:\n{concept}")
        ])

        # Inizializzazione dei 4 magazzini vettoriali
        self.vector_tech = self._init_vs("technique_vector_index", "Technique")
        self.vector_weak = self._init_vs("weakness_vector_index", "Weakness")
        self.vector_vuln = self._init_vs("vulnerability_vector_index", "Vulnerability")
        self.vector_expl = self._init_vs("exploit_vector_index", "Exploit")
        
        self.driver = GraphDatabase.driver(uri, auth=self.auth)

    def _init_vs(self, index_name, label):
        """Inizializza la connessione vettoriale per una specifica categoria."""
        return Neo4jVector.from_existing_graph(
            embedding=self.embeddings, url=self.neo4j_url, 
            username=self.auth[0], password=self.auth[1],
            index_name=index_name, node_label=label,
            text_node_properties=["description"], # Usiamo la descrizione NIST/Kali
            embedding_node_property="embedding",
            retrieval_query="RETURN node.description AS text, score, node {.*, graph_id: node.id, label: labels(node)[0]} AS metadata"
        )

    def _get_compliance_context(self, entities):
        """Attraversa il grafo per trovare i percorsi dai dati tecnici alla compliance."""
        context = []
        with self.driver.session() as session:
            for ent in entities:
                # Query ottimizzata per navigare le nuove relazioni (INSTANCE_OF, DIRECTLY_THREATENS)
                query = """
                MATCH (n) WHERE n.id = $id
                OPTIONAL MATCH (n)-[:INSTANCE_OF|EXPLOITS_VULNERABILITY|DIRECTLY_THREATENS|VIOLATES|HAS_WEAKNESS*1..3]->(r:Requirement)
                RETURN n.id as id, n.name as name, labels(n)[0] as type, n.description as desc,
                       collect(DISTINCT r.standard + ' ' + r.section + ': ' + r.name) as compliance
                """
                res = session.run(query, id=ent['id']).single()
                if res:
                    comp = ", ".join(res['compliance']) if res['compliance'] else "Nessun percorso di compliance trovato"
                    name_str = res['name'] if res['name'] else "N/A"
                    context.append(f"🔍 [{res['type']}] {res['id']} ({name_str})\nDEF: {res['desc'][:500]}\nNORME: {comp}")
        return "\n\n".join(context)

    def analyze_content(self, path_str):
        path = Path(path_str)
        workspace_data = {}

        # Caricamento file per l'analisi del concetto tecnico
        files = list(path.rglob('*')) if path.is_dir() else [path]
        for f_path in files:
            if f_path.is_file() and f_path.suffix in ['.py', '.c', '.cpp', '.js']:
                with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                    workspace_data[f_path.name] = f.read()

        if not workspace_data: return "Nessun codice trovato.", []
        full_context = "\n".join([f"--- FILE: {n} ---\n{c}" for n, c in workspace_data.items()])

        # 1. Estrazione Concetto tramite LLM
        concept = (self.concept_prompt | self.llm | StrOutputParser()).invoke({"code": full_context[:8000]})
        print(f"🎯 Concetto tecnico estratto: {concept[:100]}...")

        # 2. Ricerca Semantica Multi-Livello
        print("🔎 Ricerca semantica nel grafo (Techniques, Weaknesses, CVEs, Exploits)...")
        results = []
        results.extend(self.vector_tech.similarity_search(concept, k=2))
        results.extend(self.vector_weak.similarity_search(concept, k=3))
        results.extend(self.vector_vuln.similarity_search(concept, k=2))
        results.extend(self.vector_expl.similarity_search(concept, k=2))
        
        entities = [{'id': d.metadata['graph_id'], 'label': d.metadata['label']} for d in results]
        
        # 3. Traversing del Grafo e Report Finale
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
        # Percorso alla cartella con i tuoi file di test
        report, found = analyst.analyze_content("../testing/hardcoded_creds.py")
        print("\n" + "═"*30 + " REPORT DI ANALISI IBRIDA " + "═"*30)
        print(report)
        print("═"*86)
    finally:
        analyst.close()